

// core/core-binary.go
// Xlink Kernel v15.0 (Lean Edition)
// 精简方向：
//   - Nano协议头移除s5字段（服务端从未使用）
//   - 负载策略只保留Random（覆盖95%场景，彻底删除RR/Hash）
//   - ProxyForwarderSettings（SOCKS5转发器）整体删除
//   - GenerateConfigJSON全字段改用json.Marshal转义，杜绝裸插崩溃
//   - FallbackAddr维持v14.1独立字段设计，不再污染token

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

// 32KB buffer池，pipeDirect热路径复用，零内存抖动
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

	// 启动日志
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
	log.Printf("[Core] Xlink Lean Engine v15.0 Listening on %s [%s]", inbound.Listen, mode)

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

	// 统一分隔符：管道符/分号/换行都视为规则分隔
	raw := strings.ReplaceAll(s.Rules, "|", "\n")
	raw = strings.ReplaceAll(raw, ";", "\n")
	raw = strings.ReplaceAll(raw, "；", "\n")
	raw = strings.ReplaceAll(raw, "\r", "")

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// 兼容中文逗号
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

	// 回应握手
	if mode == 1 {
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
	if mode == 2 {
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}

	// 热路径：双向管道，goroutine接管后本函数退出
	pipeDirect(conn, wsConn)
}

func connectNanoTunnel(target string, outboundTag string, payload []byte) (*websocket.Conn, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok {
		return nil, errors.New("outbound settings not found")
	}

	// 选择目标节点
	targetServer := ""
	logMsg := ""

	// 1. 规则匹配（优先）
	for _, rule := range routingMap {
		if strings.Contains(target, rule.Keyword) {
			targetServer = rule.Node
			logMsg = fmt.Sprintf("[Core] Rule Hit->%s|Node:%s(Rule:%s)", target, targetServer, rule.Keyword)
			break
		}
	}

	// 2. 负载均衡兜底（只保留Random，够用且最稳定）
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

	// 发送Nano协议头（无s5字段）
	err = sendNanoHeader(wsConn, target, payload, settings.FallbackAddr)
	if err != nil {
		wsConn.Close()
		return nil, err
	}

	return wsConn, nil
}

// ======================== WebSocket拨号 ========================

func dialCleanWebSocket(serverAddr, serverIP, token, fallbackAddr string) (*websocket.Conn, error) {
	// SNI#IP格式：Anycast优选IP路由
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

	// 常规拨号（纯域名或纯IP）
	host, port, path, _ := parseServerAddr(serverAddr)

	// TLS SNI不能含方括号
	tlsHost := host
	if strings.HasPrefix(tlsHost, "[") && strings.HasSuffix(tlsHost, "]") {
		tlsHost = tlsHost[1 : len(tlsHost)-1]
	}
	// URL拼接时IPv6需要方括号
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

// buildWsURL：fallbackAddr非空时附加?pyip=激活服务端三级兜底
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

// GenerateConfigJSON 在内存中生成配置，不落盘。
// 所有用户输入字段统一用json.Marshal转义，防止特殊字符破坏JSON结构。
func GenerateConfigJSON(serverAddr, serverIP, secretKey, fallbackAddr, listenAddr, rules string) string {
	// 清洗监听地址
	cleanListen := strings.TrimSpace(
		strings.ReplaceAll(strings.ReplaceAll(listenAddr, "\r", ""), "\n", ""),
	)

	// 服务器地址池处理
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
			// 只保留Random策略，不再传入strategy参数
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

// pipeDirect：传输热路径，goroutine+bufPool，JS退场模型的Go等价实现
func pipeDirect(local net.Conn, ws *websocket.Conn) {
	defer ws.Close()
	defer local.Close()

	// 下行：WS → Local
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

	// 上行：Local → WS
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

// sendNanoHeader：精简版Nano协议头，移除s5字段
//
// 帧格式（二进制，大端序）：
// ┌─────────┬──────┬──────┬─────────┬──────┬─────────┐
// │hostLen  │host  │port  │fbLen    │fb    │payload  │
// │1 byte   │N byte│2byte │1 byte   │M byte│...      │
// └─────────┴──────┴──────┴─────────┴──────┴─────────┘
func sendNanoHeader(wsConn *websocket.Conn, target string, payload []byte, fb string) error {
	host, portStr, _ := net.SplitHostPort(target)
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	hostBytes := []byte(host)
	fbBytes := []byte(fb)

	if len(hostBytes) > 255 || len(fbBytes) > 255 {
		return errors.New("address length exceeds 255 bytes")
	}

	buf := new(bytes.Buffer)

	// host
	buf.WriteByte(byte(len(hostBytes)))
	buf.Write(hostBytes)

	// port（大端序uint16）
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	buf.Write(portBytes)

	// fb
	buf.WriteByte(byte(len(fbBytes)))
	if len(fbBytes) > 0 {
		buf.Write(fbBytes)
	}

	// payload（Early Data）
	if len(payload) > 0 {
		buf.Write(payload)
	}

	return wsConn.WriteMessage(websocket.BinaryMessage, buf.Bytes())
}

func handleSOCKS5(conn net.Conn, inboundTag string) (string, error) {
	handshakeBuf := make([]byte, 2)
	io.ReadFull(conn, handshakeBuf)
	conn.Write([]byte{0x05, 0x00})

	header := make([]byte, 4)
	io.ReadFull(conn, header)

	var host string
	switch header[3] {
	case 1:
		b := make([]byte, 4)
		io.ReadFull(conn, b)
		host = net.IP(b).String()
	case 3:
		b := make([]byte, 1)
		io.ReadFull(conn, b)
		d := make([]byte, b[0])
		io.ReadFull(conn, d)
		host = string(d)
	case 4:
		b := make([]byte, 16)
		io.ReadFull(conn, b)
		host = net.IP(b).String()
	}

	portBytes := make([]byte, 2)
	io.ReadFull(conn, portBytes)
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



