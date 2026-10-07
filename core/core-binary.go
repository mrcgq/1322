





//文件二：core/core-binary.go (Go 内核引擎 S 级完全体)

// =========================================================================================
// core/core-binary.go
// Xlink Odyssey Kernel Engine v14.0 (S-Tier Industrial Edition)
// [特性] 纯内存配置注入、TLV 结构化遥测输出、滑动空闲超时 (Sliding Idle Deadline) 防泄漏
// =========================================================================================

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
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

var globalRRIndex uint64

// ======================== 结构体与常量定义 ========================

const (
	EventLog    uint8 = 0x01
	EventRule   uint8 = 0x02
	EventLB     uint8 = 0x03
	EventReady  uint8 = 0x04
	EventDirect uint8 = 0x05
	EventError  uint8 = 0x06

	IdleTimeout = 60 * time.Second
)

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

type RawInputConfig struct {
	Listen   string `json:"listen"`
	Server   string `json:"server"`
	IP       string `json:"ip"`
	Token    string `json:"token"`
	Key      string `json:"key"`
	Fallback string `json:"fallback"`
	Strategy string `json:"strategy"`
	Rules    string `json:"rules"`
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

// ======================== 全局状态与缓冲池 ========================

var (
	globalConfig     Config
	proxySettingsMap = make(map[string]ProxySettings)
	routingMap       []Rule
	stdoutMu         sync.Mutex
)

var bufPool = sync.Pool{New: func() interface{} { return make([]byte, 32*1024) }}

// ======================== 结构化 TLV 遥测协议 ========================

func EmitEvent(eventType uint8, payload []byte) {
	stdoutMu.Lock()
	defer stdoutMu.Unlock()

	header := make([]byte, 5)
	binary.BigEndian.PutUint16(header[0:2], 0x5845) // 魔数 "XE"
	header[2] = eventType
	binary.BigEndian.PutUint16(header[3:5], uint16(len(payload)))

	_, _ = os.Stdout.Write(header)
	_, _ = os.Stdout.Write(payload)
}

func EmitLog(msg string) {
	EmitEvent(EventLog, []byte(msg))
}

func EmitReady(listenAddr, mode string) {
	msg := fmt.Sprintf("Listening on %s [%s]", listenAddr, mode)
	EmitEvent(EventReady, []byte(msg))
}

func EmitRuleHit(target, node, rule string) {
	msg := fmt.Sprintf("目标: %-22s -> 节点: %s (命中关键词: %s)", target, node, rule)
	EmitEvent(EventRule, []byte(msg))
}

func EmitLB(target, node, strategy string) {
	msg := fmt.Sprintf("目标: %-22s -> 节点: %s (策略: %s)", target, node, strategy)
	EmitEvent(EventLB, []byte(msg))
}

func EmitDirect(target, node string) {
	msg := fmt.Sprintf("目标: %-22s -> 节点: %s", target, node)
	EmitEvent(EventDirect, []byte(msg))
}

func EmitError(msg string) {
	EmitEvent(EventError, []byte(msg))
}

// ======================== 核心入口 ========================

func StartInstance(configContent []byte) (net.Listener, error) {
	proxySettingsMap = make(map[string]ProxySettings)
	routingMap = nil

	var raw RawInputConfig
	if err := json.Unmarshal(configContent, &raw); err != nil {
		EmitError(fmt.Sprintf("JSON 配置反序列化失败: %v", err))
		return nil, err
	}

	assembledJSON := GenerateConfigJSON(
		raw.Server, raw.IP, raw.Key, raw.Fallback, raw.Listen, raw.Strategy, raw.Rules,
	)

	if err := json.Unmarshal([]byte(assembledJSON), &globalConfig); err != nil {
		EmitError(fmt.Sprintf("内核规格构建失败: %v", err))
		return nil, err
	}

	parseRules()
	parseOutbounds()

	if len(globalConfig.Inbounds) == 0 {
		return nil, errors.New("配置中未定义任何入站")
	}

	inbound := globalConfig.Inbounds[0]
	listener, err := net.Listen("tcp", inbound.Listen)
	if err != nil {
		EmitError(fmt.Sprintf("监听端口绑定失败 %s: %v", inbound.Listen, err))
		return nil, err
	}

	mode := "单节点模式"
	if len(globalConfig.Outbounds) > 0 {
		var s ProxySettings
		if err2 := json.Unmarshal(globalConfig.Outbounds[0].Settings, &s); err2 == nil {
			if len(s.ServerPool) > 1 {
				mode = fmt.Sprintf("负载池 (%d 节点, 策略: %s)", len(s.ServerPool), s.Strategy)
			}
			if len(routingMap) > 0 {
				mode += fmt.Sprintf(" + %d 条路由规则", len(routingMap))
			}
			if s.FallbackAddr != "" {
				mode += fmt.Sprintf(" + 回源(%s)", s.FallbackAddr)
			}
		}
	}

	EmitReady(inbound.Listen, mode)

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

// ======================== 规则与出站解析 ========================

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
	raw := s.Rules
	raw = strings.ReplaceAll(raw, "|", "\n")
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

// ======================== 连接调度与握手 ========================

func handleGeneralConnection(conn net.Conn, inboundTag string) {
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}

	var (
		target     string
		firstFrame []byte
		mode       int
		err        error
	)

	switch buf[0] {
	case 0x05:
		target, err = handleSOCKS5(conn)
		mode = 1
	default:
		target, firstFrame, mode, err = handleHTTP(conn, buf)
	}

	if err != nil || target == "" {
		return
	}

	// 零延迟握手成功回复 (防止客户端超时断连)
	switch mode {
	case 1:
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
			return
		}
	case 2:
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return
		}
	}

	wsConn, err := connectNanoTunnel(target, "proxy", firstFrame)
	if err != nil {
		EmitError(fmt.Sprintf("隧道建立失败 [%s]: %v", target, err))
		return
	}

	// 移交全链路防泄漏滑动转发
	pipeDirect(conn, wsConn)
}

// ======================== 隧道建立与选路 ========================

func connectNanoTunnel(target string, outboundTag string, payload []byte) (*websocket.Conn, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok {
		return nil, errors.New("出站配置未找到: " + outboundTag)
	}

	secretKey := settings.Token
	fallback := settings.FallbackAddr

	targetServer := ""

	// 1. 规则匹配
	for _, rule := range routingMap {
		if strings.Contains(target, rule.Keyword) {
			targetServer = rule.Node
			EmitRuleHit(target, targetServer, rule.Keyword)
			break
		}
	}

	// 2. 负载均衡选路
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
			EmitLB(target, targetServer, strategy)
		} else {
			targetServer = settings.Server
			EmitDirect(target, targetServer)
		}
	}

	wsConn, err := dialCleanWebSocket(targetServer, settings.ServerIP, fallback, secretKey)
	if err != nil {
		return nil, err
	}

	if err := sendNanoHeaderV2(wsConn, target, payload, fallback); err != nil {
		wsConn.Close()
		return nil, err
	}

	return wsConn, nil
}

// ======================== WebSocket 拨号 ========================

func dialCleanWebSocket(serverAddr, serverIP, fallbackAddr, token string) (*websocket.Conn, error) {
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
		reqHeader := http.Header{}
		reqHeader.Add("Host", sniHost)
		reqHeader.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		dialer := websocket.Dialer{
			TLSClientConfig:  &tls.Config{InsecureSkipVerify: true, ServerName: sniHost},
			HandshakeTimeout: 5 * time.Second,
			NetDial: func(network, addr string) (net.Conn, error) {
				return net.DialTimeout(network, net.JoinHostPort(realIP, realPort), 5*time.Second)
			},
		}

		conn, resp, err := dialer.Dial(wsURL, reqHeader)
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
	reqHeader := http.Header{}
	reqHeader.Add("Host", tlsHost)
	reqHeader.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

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

	conn, resp, err := dialer.Dial(wsURL, reqHeader)
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

// ======================== 双向数据转发 (滑动 Deadline 卫士) ========================

func pipeDirect(local net.Conn, ws *websocket.Conn) {
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			_ = local.Close()
			_ = ws.Close()
		})
	}
	defer cleanup()

	done := make(chan struct{}, 2)

	// ── 链路 1：WS ──> TCP 本地 ─────────────────────────
	go func() {
		defer func() {
			cleanup()
			done <- struct{}{}
		}()
		buf := bufPool.Get().([]byte)
		defer bufPool.Put(buf)

		for {
			_ = ws.SetReadDeadline(time.Now().Add(IdleTimeout))
			mt, r, err := ws.NextReader()
			if err != nil {
				break
			}
			if mt == websocket.BinaryMessage {
				_ = local.SetWriteDeadline(time.Now().Add(IdleTimeout))
				if _, err := io.CopyBuffer(local, r, buf); err != nil {
					break
				}
			}
		}
	}()

	// ── 链路 2：TCP 本地 ──> WS ─────────────────────────
	go func() {
		defer func() {
			cleanup()
			done <- struct{}{}
		}()
		buf := bufPool.Get().([]byte)
		defer bufPool.Put(buf)

		for {
			_ = local.SetReadDeadline(time.Now().Add(IdleTimeout))
			n, err := local.Read(buf)
			if n > 0 {
				_ = ws.SetWriteDeadline(time.Now().Add(IdleTimeout))
				if werr := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
	}()

	<-done
}

// ======================== Nano 协议封包 ========================

func sendNanoHeaderV2(wsConn *websocket.Conn, target string, payload []byte, fb string) error {
	host, portStr, _ := net.SplitHostPort(target)
	var port uint16
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	hostBytes := []byte(host)
	fbBytes := []byte(fb)

	if len(hostBytes) > 255 {
		return errors.New("目标主机长度超过 255 字节")
	}
	if len(fbBytes) > 255 {
		return errors.New("回源地址长度超过 255 字节")
	}

	buf := new(bytes.Buffer)
	buf.WriteByte(byte(len(hostBytes)))
	buf.Write(hostBytes)

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	buf.Write(portBytes)

	buf.WriteByte(byte(len(fbBytes)))
	if len(fbBytes) > 0 {
		buf.Write(fbBytes)
	}

	if len(payload) > 0 {
		buf.Write(payload)
	}

	_ = wsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return wsConn.WriteMessage(websocket.BinaryMessage, buf.Bytes())
}

// ======================== SOCKS5 与 HTTP 解析 ========================

func handleSOCKS5(conn net.Conn) (string, error) {
	nMethodsBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, nMethodsBuf); err != nil {
		return "", err
	}

	methods := make([]byte, nMethodsBuf[0])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", err
	}

	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return "", err
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}

	var host string
	switch header[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 0x03: // 域名
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", err
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}
		host = string(domain)
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	default:
		return "", fmt.Errorf("不支持的地址类型: %d", header[3])
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBytes)

	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

func handleHTTP(conn net.Conn, initialData []byte) (string, []byte, int, error) {
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
	_ = req.WriteProxy(&buf)
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

func GenerateConfigJSON(serverAddr, serverIP, secretKey, fallbackAddr, listenAddr, strategy, rules string) string {
	cleanListen := strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(listenAddr, "\r", ""), "\n", ""))
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
			nodeJSON, _ := json.Marshal(validPool[0])
			serverJSON = fmt.Sprintf(`"server": %s`, string(nodeJSON))
		default:
			poolJSON, _ := json.Marshal(validPool)
			firstJSON, _ := json.Marshal(validPool[0])
			strategyJSON, _ := json.Marshal(strategy)
			serverJSON = fmt.Sprintf(`"server": %s, "server_pool": %s, "strategy": %s`,
				string(firstJSON), string(poolJSON), string(strategyJSON))
		}
	} else {
		nodeJSON, _ := json.Marshal(strings.TrimSpace(serverAddr))
		serverJSON = fmt.Sprintf(`"server": %s`, string(nodeJSON))
	}

	listenJSON, _ := json.Marshal(cleanListen)
	tokenJSON, _ := json.Marshal(secretKey)
	rulesJSON, _ := json.Marshal(rules)

	serverIPJSON := ""
	if serverIP != "" {
		sipJSON, _ := json.Marshal(serverIP)
		serverIPJSON = fmt.Sprintf(`, "server_ip": %s`, string(sipJSON))
	}

	fallbackJSON := ""
	if fallbackAddr != "" {
		fbJSON, _ := json.Marshal(fallbackAddr)
		fallbackJSON = fmt.Sprintf(`, "fallback_addr": %s`, string(fbJSON))
	}

	return fmt.Sprintf(
		`{`+
			`"inbounds": [{"tag": "socks-in", "listen": %s, "protocol": "socks"}],`+
			`"outbounds": [{`+
			`"tag": "proxy",`+
			`"protocol": "ech-proxy",`+
			`"settings": {`+
			`%s,`+
			`"token": %s,`+
			`"rules": %s%s%s`+
			`}`+
			`}],`+
			`"routing": {"rules": [{"outboundTag": "proxy", "port": [0, 65535]}]}`+
			`}`,
		string(listenJSON), serverJSON, string(tokenJSON), string(rulesJSON), serverIPJSON, fallbackJSON,
	)
}







