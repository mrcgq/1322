// core/core-binary.go (v14.1内核端)
// [修复 BUG-4] ProxySettings 新增独立 FallbackAddr 字段，彻底消除 | 污染 token 的问题
// [修复 BUG-5] dialCleanWebSocket 构建 wss URL 时携带 ?pyip= 参数，激活服务端级别二中转

//go:build binary
// +build binary

package core

import (
	"bufio"
	"bytes"
	"crypto/md5"
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
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

var globalRRIndex uint64

// ======================== 结构定义 ========================

type ProxySettings struct {
	Server     string   `json:"server"`
	ServerPool []string `json:"server_pool"`
	Strategy   string   `json:"strategy"`
	Rules      string   `json:"rules"`
	ServerIP   string   `json:"server_ip"`
	Token      string   `json:"token"`
	// [修复 BUG-4] 独立字段，不再与 token 用 | 合并
	FallbackAddr      string                  `json:"fallback_addr,omitempty"`
	ForwarderSettings *ProxyForwarderSettings `json:"proxy_settings,omitempty"`
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
type ProxyForwarderSettings struct {
	Socks5Address string `json:"socks5_address"`
}
type Routing struct {
	Rules           []Rule `json:"rules"`
	DefaultOutbound string `json:"defaultOutbound,omitempty"`
}

var (
	globalConfig     Config
	proxySettingsMap = make(map[string]ProxySettings)
	routingMap       []Rule
)

var bufPool = sync.Pool{New: func() interface{} { return make([]byte, 32*1024) }}

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
		return nil, errors.New("no inbounds")
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
			mode = fmt.Sprintf("Hydra Pool (%d nodes, Strategy: %s)", len(s.ServerPool), s.Strategy)
		}
		if len(routingMap) > 0 {
			mode += fmt.Sprintf(" + %d Rules", len(routingMap))
		}
		if s.FallbackAddr != "" {
			mode += fmt.Sprintf(" + Fallback(%s)", s.FallbackAddr)
		}
	}
	log.Printf("[Core] Xlink Odyssey Engine (v14.1) Listening on %s [%s]", inbound.Listen, mode)

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

	rawRules := strings.ReplaceAll(s.Rules, "|", "\n")
	rawRules = strings.ReplaceAll(rawRules, ";", "\n")
	rawRules = strings.ReplaceAll(rawRules, "；", "\n")
	rawRules = strings.ReplaceAll(rawRules, "\r", "")

	lines := strings.Split(rawRules, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.ReplaceAll(line, "，", ",")
		parts := strings.SplitN(line, ",", 2)
		if len(parts) == 2 {
			keyword := strings.TrimSpace(parts[0])
			node := strings.TrimRight(strings.TrimSpace(parts[1]), ";,.")
			if keyword != "" && node != "" {
				routingMap = append(routingMap, Rule{Keyword: keyword, Node: node})
			}
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
		return nil, errors.New("settings not found")
	}

	// [修复 BUG-4] token 就是纯净的 secretKey，不再含 | 拼接
	secretKey := settings.Token
	// [修复 BUG-4] fallback 从独立字段读取
	fallback := settings.FallbackAddr
	socks5 := ""
	if settings.ForwarderSettings != nil {
		socks5 = settings.ForwarderSettings.Socks5Address
	}

	targetServer := ""
	logMsg := ""

	// 1. 规则匹配
	for _, rule := range routingMap {
		if strings.Contains(target, rule.Keyword) {
			targetServer = rule.Node
			logMsg = fmt.Sprintf("[Core] Rule Hit -> %s | Node: %s (Rule: %s)", target, targetServer, rule.Keyword)
			break
		}
	}

	// 2. 负载均衡兜底
	if targetServer == "" {
		if len(settings.ServerPool) > 0 {
			poolLen := uint64(len(settings.ServerPool))
			strategy := settings.Strategy
			switch strategy {
			case "rr":
				idx := atomic.AddUint64(&globalRRIndex, 1)
				targetServer = settings.ServerPool[idx%poolLen]
			case "hash":
				h := md5.Sum([]byte(target))
				hashVal := binary.BigEndian.Uint64(h[:8])
				targetServer = settings.ServerPool[hashVal%poolLen]
			default:
				targetServer = settings.ServerPool[rand.Intn(int(poolLen))]
			}
			logMsg = fmt.Sprintf("[Core] LB -> %s | Node: %s | Algo: %s", target, targetServer, strategy)
		} else {
			targetServer = settings.Server
			logMsg = fmt.Sprintf("[Core] Direct -> %s | Node: %s", target, targetServer)
		}
	}

	log.Print(logMsg)

	// [修复 BUG-5] 将 serverIP 和 fallback 同时传入，由 dialCleanWebSocket 附加到 URL
	wsConn, err := dialCleanWebSocket(targetServer, settings.ServerIP, fallback, secretKey)
	if err != nil {
		return nil, err
	}

	err = sendNanoHeaderV2(wsConn, target, payload, socks5, fallback)
	if err != nil {
		wsConn.Close()
		return nil, err
	}
	return wsConn, nil
}

// ======================== WebSocket 拨号 ========================

// [修复 BUG-5] 新增 fallbackAddr 参数，构建 URL 时携带 ?pyip=，激活服务端级别二中转
func dialCleanWebSocket(serverAddr, serverIP, fallbackAddr, token string) (*websocket.Conn, error) {
	// ── SNI#IP 格式：Anycast 优选 IP 路由 ──
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

		// [修复 BUG-5] 构建含 pyip 的 URL
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

	// ── 常规拨号（纯域名或纯 IP）──
	host, port, path, _ := parseServerAddr(serverAddr)
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}

	// [修复 BUG-5] 统一通过 buildWsURL 构建，确保携带 pyip
	wsURL := buildWsURL(host+path, port, token, fallbackAddr)

	requestHeader := http.Header{}
	requestHeader.Add("Host", host)
	requestHeader.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true, ServerName: host},
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

// [修复 BUG-5] 统一 URL 构建函数：当 fallbackAddr 非空时附加 ?pyip= 激活服务端级别二中转
// 注意：path 已含前导 /，port 是端口字符串，host 可含 [IPv6]
func buildWsURL(hostWithPath, port, token, fallbackAddr string) string {
	// 拆分 host 和 path
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

func GenerateConfigJSON(serverAddr, serverIP, secretKey, socks5Addr, fallbackAddr, listenAddr, strategy, rules string) string {
	// 清洗监听地址
	cleanListen := strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(listenAddr, "\r", ""), "\n", ""))

	// [修复 BUG-4] token 字段只存 secretKey，不再拼接 fallback
	// fallback 单独写入 fallback_addr 字段

	normalizedAddr := serverAddr
	for _, r := range []string{"\r\n", "\n", "，", ",", "；"} {
		normalizedAddr = strings.ReplaceAll(normalizedAddr, r, ";")
	}

	var serverJSON string
	if strings.Contains(normalizedAddr, ";") {
		rawPool := strings.Split(normalizedAddr, ";")
		var validPool []string
		for _, node := range rawPool {
			if t := strings.TrimSpace(node); t != "" {
				validPool = append(validPool, t)
			}
		}
		switch len(validPool) {
		case 0:
			serverJSON = `"server": ""`
		case 1:
			serverJSON = fmt.Sprintf(`"server": "%s"`, validPool[0])
		default:
			poolJSON, _ := json.Marshal(validPool)
			serverJSON = fmt.Sprintf(`"server": "%s", "server_pool": %s, "strategy": "%s"`,
				validPool[0], string(poolJSON), strategy)
		}
	} else {
		serverJSON = fmt.Sprintf(`"server": "%s"`, strings.TrimSpace(serverAddr))
	}

	rulesJSON, _ := json.Marshal(rules)

	// [修复 BUG-4] fallback_addr 独立字段，token 保持纯净
	fallbackJSON := ""
	if fallbackAddr != "" {
		fallbackJSON = fmt.Sprintf(`, "fallback_addr": "%s"`, fallbackAddr)
	}

	serverIPJSON := ""
	if serverIP != "" {
		serverIPJSON = fmt.Sprintf(`, "server_ip": "%s"`, serverIP)
	}

	config := fmt.Sprintf(`{
	"inbounds": [{"tag": "socks-in", "listen": "%s", "protocol": "socks"}],
	"outbounds": [{
		"tag": "proxy",
		"protocol": "ech-proxy",
		"settings": {
			%s,
			"token": "%s",
			"rules": %s%s%s`,
		cleanListen, serverJSON, secretKey, string(rulesJSON), serverIPJSON, fallbackJSON)

	if socks5Addr != "" {
		config += fmt.Sprintf(`, "proxy_settings": {"socks5_address": "%s"}`, socks5Addr)
	}
	config += `}}], "routing": {"rules": [{"outboundTag": "proxy", "port": [0, 65535]}]}}`
	return config
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
	bufPtr := bufPool.Get().([]byte)
	defer bufPool.Put(bufPtr)
	for {
		n, err := local.Read(bufPtr)
		if n > 0 {
			if err := ws.WriteMessage(websocket.BinaryMessage, bufPtr[:n]); err != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
}

func sendNanoHeaderV2(wsConn *websocket.Conn, target string, payload []byte, s5 string, fb string) error {
	host, portStr, _ := net.SplitHostPort(target)
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	hostBytes := []byte(host)
	s5Bytes := []byte(s5)
	fbBytes := []byte(fb)
	if len(hostBytes) > 255 || len(s5Bytes) > 255 || len(fbBytes) > 255 {
		return errors.New("address length exceeds 255 bytes")
	}
	buf := new(bytes.Buffer)
	buf.WriteByte(byte(len(hostBytes)))
	buf.Write(hostBytes)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	buf.Write(portBytes)
	buf.WriteByte(byte(len(s5Bytes)))
	if len(s5Bytes) > 0 {
		buf.Write(s5Bytes)
	}
	buf.WriteByte(byte(len(fbBytes)))
	if len(fbBytes) > 0 {
		buf.Write(fbBytes)
	}
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
