// core/core-binary.go
// Xlink Kernel v15.1 (Lean Edition)
// 修复：
//   - hostLen校验统一为253（与Worker/Snippets对齐）
//   - port解析改strconv，错误明确返回
//   - handleSOCKS5正确跳过METHODS字节（修复协议解析bug）

//go:build binary
// +build binary

package core

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ======================== 结构定义 ========================

type ProxySettings struct {
	Server       string   `json:"server"`
	ServerPool   []string `json:"server_pool"`
	Strategy     string   `json:"strategy"`
	Rules        string   `json:"rules"`
	ServerIP     string   `json:"server_ip"`
	Token        string   `json:"token"`
	FallbackAddr string   `json:"fallback_addr,omitempty"`
}

type Rule struct {
	Keyword string
	Node    string
}

type Config struct {
	Inbounds  []Inbound  `json:"inbounds"`
	Outbounds []Outbound `json:"outbounds"`
	Routing   Routing    `json:"routing"`
}

type Inbound struct {
	Tag      string `json:"tag"`
	Listen   string `json:"listen"`
	Protocol string `json:"protocol"`
}

type Outbound struct {
	Tag      string          `json:"tag"`
	Protocol string          `json:"protocol"`
	Settings json.RawMessage `json:"settings,omitempty"`
}

type Routing struct {
	Rules           []Rule `json:"rules"`
	DefaultOutbound string `json:"defaultOutbound,omitempty"`
}

// ======================== 全局状态 ========================

var (
	globalConfig     Config
	proxySettingsMap = make(map[string]ProxySettings)
	routingMap       []Rule
)

// 32KB buffer池，pipeDirect热路径复用
var bufPool = sync.Pool{
	New: func() interface{} { return make([]byte, 32*1024) },
}

// ======================== 核心入口 ========================

func StartInstance(configContent []byte) (net.Listener, error) {
	rand.Seed(time.Now().UnixNano())
	proxySettingsMap = make(map[string]ProxySettings)
	routingMap = nil

	if err := json.Unmarshal(configContent, &globalConfig); err != nil {
		return nil, err
	}

	parseRules()
	parseOutbounds()

	if len(globalConfig.Inbounds) == 0 {
		return nil, errors.New("no inbounds configured")
	}

	inbound := globalConfig.Inbounds[0]
	listener, err := net.Listen("tcp", inbound.Listen)
	if err != nil {
		return nil, err
	}

	mode := "Single Node"
	if len(globalConfig.Outbounds) > 0 {
		var s ProxySettings
		json.Unmarshal(globalConfig.Outbounds[0].Settings, &s)
		if len(s.ServerPool) > 1 {
			mode = fmt.Sprintf("Pool(%d nodes)", len(s.ServerPool))
		}
		if len(routingMap) > 0 {
			mode += fmt.Sprintf("+%d Rules", len(routingMap))
		}
		if s.FallbackAddr != "" {
			mode += "+Fallback"
		}
	}
	log.Printf("[Core] Xlink Lean Engine v15.1 Listening on %s [%s]", inbound.Listen, mode)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				break
			}
			go handleGeneralConnection(conn, inbound.Tag)
		}
	}()

	return listener, nil
}

// ======================== 规则解析 ========================

func parseRules() {
	if len(globalConfig.Outbounds) == 0 {
		return
	}
	var s ProxySettings
	if err := json.Unmarshal(globalConfig.Outbounds[0].Settings, &s); err != nil {
		return
	}
	if s.Rules == "" {
		return
	}

	raw := strings.ReplaceAll(s.Rules, "|", "\n")
	raw = strings.ReplaceAll(raw, ";", "\n")
	raw = strings.ReplaceAll(raw, "；", "\n")
	raw = strings.ReplaceAll(raw, "\r", "")

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.ReplaceAll(line, "，", ",")
		parts := strings.SplitN(line, ",", 2)
		if len(parts) != 2 {
			continue
		}
		keyword := strings.TrimSpace(parts[0])
		node := strings.TrimRight(strings.TrimSpace(parts[1]), ";,.")
		if keyword != "" && node != "" {
			routingMap = append(routingMap, Rule{Keyword: keyword, Node: node})
		}
	}
}

func parseOutbounds() {
	for _, outbound := range globalConfig.Outbounds {
		if outbound.Protocol == "ech-proxy" {
			var settings ProxySettings
			if err := json.Unmarshal(outbound.Settings, &settings); err == nil {
				proxySettingsMap[outbound.Tag] = settings
			}
		}
	}
}

// ======================== 连接处理 ========================

func handleGeneralConnection(conn net.Conn, inboundTag string) {
	defer conn.Close()

	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}

	var target string
	var err error
	var firstFrame []byte
	var mode int

	switch buf[0] {
	case 0x05:
		target, err = handleSOCKS5(conn, inboundTag)
		mode = 1
	default:
		target, firstFrame, mode, err = handleHTTP(conn, buf, inboundTag)
	}
	if err != nil {
		return
	}

	wsConn, err := connectNanoTunnel(target, "proxy", firstFrame)
	if err != nil {
		log.Printf("[Core] Error connecting to %s: %v", target, err)
		return
	}

	if mode == 1 {
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
	if mode == 2 {
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}

	pipeDirect(conn, wsConn)
}

func connectNanoTunnel(target string, outboundTag string, payload []byte) (*websocket.Conn, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok {
		return nil, errors.New("outbound settings not found")
	}

	targetServer := ""
	logMsg := ""

	for _, rule := range routingMap {
		if strings.Contains(target, rule.Keyword) {
			targetServer = rule.Node
			logMsg = fmt.Sprintf("[Core] Rule Hit->%s|Node:%s(Rule:%s)", target, targetServer, rule.Keyword)
			break
		}
	}

	if targetServer == "" {
		if len(settings.ServerPool) > 0 {
			targetServer = settings.ServerPool[rand.Intn(len(settings.ServerPool))]
			logMsg = fmt.Sprintf("[Core] LB->%s|Node:%s|Algo:random", target, targetServer)
		} else {
			targetServer = settings.Server
			logMsg = fmt.Sprintf("[Core] Direct->%s|Node:%s", target, targetServer)
		}
	}

	log.Print(logMsg)

	wsConn, err := dialCleanWebSocket(targetServer, settings.ServerIP, settings.Token, settings.FallbackAddr)
	if err != nil {
		return nil, err
	}

	if err = sendNanoHeader(wsConn, target, payload, settings.FallbackAddr); err != nil {
		wsConn.Close()
		return nil, err
	}

	return wsConn, nil
}

// ======================== WebSocket拨号 ========================

func dialCleanWebSocket(serverAddr, serverIP, token, fallbackAddr string) (*websocket.Conn, error) {
	parts := strings.SplitN(serverAddr, "#", 2)
	if len(parts) == 2 {
		sni := strings.TrimSpace(parts[0])
		realAddr := strings.TrimSpace(parts[1])

		sniHost, sniPort, err := net.SplitHostPort(sni)
		if err != nil {
			sniHost = sni
			sniPort = "443"
		}

		realIP, realPort, err := net.SplitHostPort(realAddr)
		if err != nil {
			realIP = realAddr
			realPort = sniPort
		}

		wsURL := buildWsURL(sniHost, realPort, token, fallbackAddr)

		requestHeader := http.Header{}
		requestHeader.Add("Host", sniHost)
		requestHeader.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		dialer := websocket.Dialer{
			TLSClientConfig:  &tls.Config{InsecureSkipVerify: true, ServerName: sniHost},
			HandshakeTimeout: 5 * time.Second,
			NetDial: func(network, addr string) (net.Conn, error) {
				return net.DialTimeout(network, net.JoinHostPort(realIP, realPort), 5*time.Second)
			},
		}

		conn, resp, err := dialer.Dial(wsURL, requestHeader)
		if err != nil {
			if resp != nil {
				return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
			}
			return nil, err
		}
		return conn, nil
	}

	host, port, path, _ := parseServerAddr(serverAddr)

	tlsHost := host
	if strings.HasPrefix(tlsHost, "[") && strings.HasSuffix(tlsHost, "]") {
		tlsHost = tlsHost[1 : len(tlsHost)-1]
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}

	wsURL := buildWsURL(host+path, port, token, fallbackAddr)

	requestHeader := http.Header{}
	requestHeader.Add("Host", tlsHost)
	requestHeader.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true, ServerName: tlsHost},
		HandshakeTimeout: 5 * time.Second,
	}

	if serverIP != "" {
		dialer.NetDial = func(network, addr string) (net.Conn, error) {
			_, p, _ := net.SplitHostPort(addr)
			return net.DialTimeout(network, net.JoinHostPort(serverIP, p), 5*time.Second)
		}
	}

	conn, resp, err := dialer.Dial(wsURL, requestHeader)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return nil, err
	}
	return conn, nil
}

func buildWsURL(hostWithPath, port, token, fallbackAddr string) string {
	host := hostWithPath
	path := "/"
	if idx := strings.Index(hostWithPath, "/"); idx != -1 {
		path = hostWithPath[idx:]
		host = hostWithPath[:idx]
	}
	base := fmt.Sprintf("wss://%s:%s%s?token=%s", host, port, path, url.QueryEscape(token))
	if fallbackAddr != "" {
		base += "&pyip=" + url.QueryEscape(fallbackAddr)
	}
	return base
}

// ======================== 配置生成 ========================

func GenerateConfigJSON(serverAddr, serverIP, secretKey, fallbackAddr, listenAddr, rules string) string {
	cleanListen := strings.TrimSpace(
		strings.ReplaceAll(strings.ReplaceAll(listenAddr, "\r", ""), "\n", ""),
	)

	normalized := serverAddr
	for _, sep := range []string{"\r\n", "\n", "，", ",", "；"} {
		normalized = strings.ReplaceAll(normalized, sep, ";")
	}

	var serverJSON string
	if strings.Contains(normalized, ";") {
		rawPool := strings.Split(normalized, ";")
		var validPool []string
		for _, node := range rawPool {
			if t := strings.TrimSpace(node); t != "" {
				validPool = append(validPool, t)
			}
		}
		switch len(validPool) {
		case 0:
			serverJSON = `"server":""`
		case 1:
			nodeJSON, _ := json.Marshal(validPool[0])
			serverJSON = fmt.Sprintf(`"server":%s`, string(nodeJSON))
		default:
			poolJSON, _ := json.Marshal(validPool)
			firstJSON, _ := json.Marshal(validPool[0])
			serverJSON = fmt.Sprintf(`"server":%s,"server_pool":%s,"strategy":"random"`,
				string(firstJSON), string(poolJSON))
		}
	} else {
		nodeJSON, _ := json.Marshal(strings.TrimSpace(serverAddr))
		serverJSON = fmt.Sprintf(`"server":%s`, string(nodeJSON))
	}

	tokenJSON, _ := json.Marshal(secretKey)
	rulesJSON, _ := json.Marshal(rules)

	serverIPJSON := ""
	if serverIP != "" {
		sipJSON, _ := json.Marshal(serverIP)
		serverIPJSON = fmt.Sprintf(`,"server_ip":%s`, string(sipJSON))
	}

	fallbackJSON := ""
	if fallbackAddr != "" {
		fbJSON, _ := json.Marshal(fallbackAddr)
		fallbackJSON = fmt.Sprintf(`,"fallback_addr":%s`, string(fbJSON))
	}

	return fmt.Sprintf(
		`{"inbounds":[{"tag":"socks-in","listen":"%s","protocol":"socks"}],"outbounds":[{"tag":"proxy","protocol":"ech-proxy","settings":{%s,"token":%s,"rules":%s%s%s}}],"routing":{"rules":[{"outboundTag":"proxy","port":[0,65535]}]}}`,
		cleanListen,
		serverJSON,
		string(tokenJSON),
		string(rulesJSON),
		serverIPJSON,
		fallbackJSON,
	)
}

// ======================== 辅助函数 ========================

func pipeDirect(local net.Conn, ws *websocket.Conn) {
	defer ws.Close()
	defer local.Close()

	go func() {
		buf := bufPool.Get().([]byte)
		defer bufPool.Put(buf)
		for {
			mt, r, err := ws.NextReader()
			if err != nil {
				break
			}
			if mt == websocket.BinaryMessage {
				if _, err := io.CopyBuffer(local, r, buf); err != nil {
					break
				}
			}
		}
		local.Close()
	}()

	buf := bufPool.Get().([]byte)
	defer bufPool.Put(buf)
	for {
		n, err := local.Read(buf)
		if n > 0 {
			if err := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
}

// sendNanoHeader：Nano协议头
// 帧格式：hostLen(1)|host(N)|port(2,大端)|fbLen(1)|fb(M)|payload
func sendNanoHeader(wsConn *websocket.Conn, target string, payload []byte, fb string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("invalid target %q: %w", target, err)
	}

	// 修复：用strconv替代fmt.Sscanf，错误明确返回
	portNum, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || portNum == 0 {
		return fmt.Errorf("invalid port %q", portStr)
	}

	hostBytes := []byte(host)
	fbBytes := []byte(fb)

	// 修复：统一为253，与Worker/Snippets对齐
	if len(hostBytes) > 253 || len(fbBytes) > 253 {
		return errors.New("address length exceeds 253 bytes")
	}

	buf := new(bytes.Buffer)

	buf.WriteByte(byte(len(hostBytes)))
	buf.Write(hostBytes)

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(portNum))
	buf.Write(portBytes)

	buf.WriteByte(byte(len(fbBytes)))
	if len(fbBytes) > 0 {
		buf.Write(fbBytes)
	}

	if len(payload) > 0 {
		buf.Write(payload)
	}

	return wsConn.WriteMessage(websocket.BinaryMessage, buf.Bytes())
}

// handleSOCKS5：修复METHODS字节跳过bug
func handleSOCKS5(conn net.Conn, inboundTag string) (string, error) {
	// 读 VER + NMETHODS
	meta := make([]byte, 2)
	if _, err := io.ReadFull(conn, meta); err != nil {
		return "", err
	}
	// 跳过 NMETHODS 个 METHOD 字节，否则后续读取错位
	if meta[1] > 0 {
		methods := make([]byte, meta[1])
		if _, err := io.ReadFull(conn, methods); err != nil {
			return "", err
		}
	}
	// 回应：选择无需认证
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return "", err
	}

	// 读请求头：VER CMD RSV ATYP
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}

	var host string
	switch header[3] {
	case 1: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 3: // 域名
		b := make([]byte, 1)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		d := make([]byte, b[0])
		if _, err := io.ReadFull(conn, d); err != nil {
			return "", err
		}
		host = string(d)
	case 4: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	default:
		return "", fmt.Errorf("unsupported SOCKS5 ATYP: %d", header[3])
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBytes)
	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

func handleHTTP(conn net.Conn, initialData []byte, inboundTag string) (string, []byte, int, error) {
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return "", nil, 0, err
	}

	target := req.Host
	if !strings.Contains(target, ":") {
		if req.Method == "CONNECT" {
			target += ":443"
		} else {
			target += ":80"
		}
	}

	if req.Method == "CONNECT" {
		return target, nil, 2, nil
	}

	var buf bytes.Buffer
	req.WriteProxy(&buf)
	return target, buf.Bytes(), 3, nil
}

func parseServerAddr(addr string) (host, port, path string, err error) {
	path = "/"
	if idx := strings.Index(addr, "/"); idx != -1 {
		path = addr[idx:]
		addr = addr[:idx]
	}
	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "443"
		err = nil
	}
	return
}
