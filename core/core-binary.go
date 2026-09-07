// =========================================================================================
// core/core-binary.go
// Xlink Odyssey 内核端 v14.2
// [变更] 删除 s5 出站代理功能（层次二）
//        · 移除 ProxyForwarderSettings 结构体
//        · 移除 ProxySettings.ForwarderSettings 字段
//        · sendNanoHeaderV2 协议头不再写入 s5 字段
//        · GenerateConfigJSON 移除 socks5Addr 参数
//        · handleSOCKS5 全部 IO 调用加错误检查
//        · 移除已弃用的 rand.Seed()
// [修复] SOCKS5/HTTP CONNECT 握手响应提前至隧道建立之前（时序修复）
// [修复] GenerateConfigJSON 中 cleanListen 统一经 json.Marshal 转义
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

// ProxySettings 承载出站代理的核心配置。
// s5 / ForwarderSettings 已删除（v14.2）。
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

// 32KB 读写缓冲池，复用避免 GC 压力
var bufPool = sync.Pool{New: func() interface{} { return make([]byte, 32*1024) }}

// ======================== 核心入口 ========================

// StartInstance 解析配置 JSON，启动监听，返回 Listener 供调用方管理生命周期。
func StartInstance(configContent []byte) (net.Listener, error) {
	// 注意：Go 1.20+ 全局 rand 已自动种子化，无需 rand.Seed()
	proxySettingsMap = make(map[string]ProxySettings)
	routingMap = nil

	if err := json.Unmarshal(configContent, &globalConfig); err != nil {
		return nil, fmt.Errorf("config parse error: %w", err)
	}

	parseRules()
	parseOutbounds()

	if len(globalConfig.Inbounds) == 0 {
		return nil, errors.New("no inbounds defined in config")
	}

	inbound := globalConfig.Inbounds[0]
	listener, err := net.Listen("tcp", inbound.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen failed on %s: %w", inbound.Listen, err)
	}

	// 构建启动模式描述日志
	mode := "Single Node"
	if len(globalConfig.Outbounds) > 0 {
		var s ProxySettings
		if err2 := json.Unmarshal(globalConfig.Outbounds[0].Settings, &s); err2 == nil {
			if len(s.ServerPool) > 1 {
				mode = fmt.Sprintf("Hydra Pool (%d nodes, Strategy: %s)",
					len(s.ServerPool), s.Strategy)
			}
			if len(routingMap) > 0 {
				mode += fmt.Sprintf(" + %d Rules", len(routingMap))
			}
			if s.FallbackAddr != "" {
				mode += fmt.Sprintf(" + Fallback(%s)", s.FallbackAddr)
			}
		}
	}

	log.Printf("[Core] Xlink Odyssey Engine (v14.2) Listening on %s [%s]",
		inbound.Listen, mode)

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

// parseRules 从第一个出站配置里读取 rules 字符串并解析为路由表。
// 支持 | ; ；\n 多种分隔符，忽略注释行（# 开头）。
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
	raw = strings.ReplaceAll(raw, "|",  "\n")
	raw = strings.ReplaceAll(raw, ";",  "\n")
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
			node    := strings.TrimRight(strings.TrimSpace(parts[1]), ";,.")
			if keyword != "" && node != "" {
				routingMap = append(routingMap, Rule{Keyword: keyword, Node: node})
			}
		}
	}
}

// parseOutbounds 将所有 ech-proxy 出站配置索引到 proxySettingsMap。
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

// handleGeneralConnection 识别入站协议类型（SOCKS5 / HTTP CONNECT / HTTP 明文），
// 解析目标地址后先向客户端发送握手响应，再建立 WebSocket 隧道并双向转发。
//
// 时序（修复后）：
//   1. 识别协议，解析目标地址
//   2. 向客户端发送握手成功响应（SOCKS5 / HTTP CONNECT）
//   3. 建立上游 WebSocket 隧道
//   4. 双向转发
//
// 修复前的错误时序为先建隧道再回复客户端，导致客户端在网络延迟期间超时断连。
func handleGeneralConnection(conn net.Conn, inboundTag string) {
	defer conn.Close()

	// 读取协议首字节以区分 SOCKS5 与 HTTP
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
		// SOCKS5 入站
		target, err = handleSOCKS5(conn)
		mode = 1
	default:
		// HTTP 入站
		target, firstFrame, mode, err = handleHTTP(conn, buf)
	}

	if err != nil || target == "" {
		return
	}

	// ── 步骤一：先向客户端发送握手响应 ──────────────────────────
	// 必须在建立上游隧道之前完成，否则客户端因等待响应超时而断开。
	// mode==3（HTTP 明文转发）无需预回复，firstFrame 已含完整请求体。
	switch mode {
	case 1: // SOCKS5
		if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
			return
		}
	case 2: // HTTP CONNECT
		if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return
		}
	}

	// ── 步骤二：建立上游 WebSocket 隧道 ─────────────────────────
	wsConn, err := connectNanoTunnel(target, "proxy", firstFrame)
	if err != nil {
		log.Printf("[Core] Error connecting to %s: %v", target, err)
		return
	}

	// ── 步骤三：双向转发 ─────────────────────────────────────────
	pipeDirect(conn, wsConn)
}

// ======================== 隧道建立 ========================

// connectNanoTunnel 依据路由规则或负载均衡策略选出目标节点，
// 建立 WebSocket 连接并发送 Nano 协议头。
func connectNanoTunnel(target string, outboundTag string, payload []byte) (*websocket.Conn, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok {
		return nil, errors.New("outbound settings not found: " + outboundTag)
	}

	secretKey := settings.Token
	fallback  := settings.FallbackAddr

	targetServer := ""
	logMsg       := ""

	// 第一优先级：规则匹配
	for _, rule := range routingMap {
		if strings.Contains(target, rule.Keyword) {
			targetServer = rule.Node
			logMsg = fmt.Sprintf("[Core] Rule Hit -> %s | Node: %s (Rule: %s)",
				target, targetServer, rule.Keyword)
			break
		}
	}

	// 第二优先级：负载均衡
	if targetServer == "" {
		if len(settings.ServerPool) > 0 {
			poolLen  := uint64(len(settings.ServerPool))
			strategy := settings.Strategy
			switch strategy {
			case "rr":
				idx          := atomic.AddUint64(&globalRRIndex, 1)
				targetServer  = settings.ServerPool[idx%poolLen]
			case "hash":
				h            := md5.Sum([]byte(target))
				hashVal       := binary.BigEndian.Uint64(h[:8])
				targetServer  = settings.ServerPool[hashVal%poolLen]
			default:
				targetServer = settings.ServerPool[rand.Intn(int(poolLen))]
			}
			logMsg = fmt.Sprintf("[Core] LB -> %s | Node: %s | Algo: %s",
				target, targetServer, strategy)
		} else {
			targetServer = settings.Server
			logMsg = fmt.Sprintf("[Core] Direct -> %s | Node: %s",
				target, targetServer)
		}
	}

	log.Print(logMsg)

	wsConn, err := dialCleanWebSocket(targetServer, settings.ServerIP, fallback, secretKey)
	if err != nil {
		return nil, err
	}

	// 发送 Nano 协议头（不含 s5 字段）
	if err := sendNanoHeaderV2(wsConn, target, payload, fallback); err != nil {
		wsConn.Close()
		return nil, err
	}

	return wsConn, nil
}

// ======================== WebSocket 拨号 ========================

// dialCleanWebSocket 建立出站 WSS 连接。
// 支持 SNI#IP 格式（Anycast 优选）和常规域名/IP 格式。
func dialCleanWebSocket(serverAddr, serverIP, fallbackAddr, token string) (*websocket.Conn, error) {

	// ── SNI#IP 格式：Anycast 优选 IP 路由 ──────────────────────
	parts := strings.SplitN(serverAddr, "#", 2)
	if len(parts) == 2 {
		sni      := strings.TrimSpace(parts[0])
		realAddr := strings.TrimSpace(parts[1])

		sniHost, sniPort, err := net.SplitHostPort(sni)
		if err != nil {
			sniHost = sni
			sniPort = "443"
		}

		realIP, realPort, err := net.SplitHostPort(realAddr)
		if err != nil {
			realIP   = realAddr
			realPort = sniPort
		}

		wsURL := buildWsURL(sniHost, realPort, token, fallbackAddr)
		reqHeader := http.Header{}
		reqHeader.Add("Host",       sniHost)
		reqHeader.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		dialer := websocket.Dialer{
			TLSClientConfig:  &tls.Config{InsecureSkipVerify: true, ServerName: sniHost},
			HandshakeTimeout: 5 * time.Second,
			NetDial: func(network, addr string) (net.Conn, error) {
				return net.DialTimeout(network,
					net.JoinHostPort(realIP, realPort), 5*time.Second)
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

	// ── 常规拨号（纯域名或纯 IP）─────────────────────────────────
	host, port, path, _ := parseServerAddr(serverAddr)

	// [IPv6 修复] TLS SNI 和 Host 头不能含方括号
	tlsHost := host
	if strings.HasPrefix(tlsHost, "[") && strings.HasSuffix(tlsHost, "]") {
		tlsHost = tlsHost[1 : len(tlsHost)-1]
	}

	// [IPv6 修复] URL 拼接时裸 IPv6 需要方括号
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}

	wsURL := buildWsURL(host+path, port, token, fallbackAddr)
	reqHeader := http.Header{}
	reqHeader.Add("Host",       tlsHost)
	reqHeader.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true, ServerName: tlsHost},
		HandshakeTimeout: 5 * time.Second,
	}

	if serverIP != "" {
		dialer.NetDial = func(network, addr string) (net.Conn, error) {
			_, p, _ := net.SplitHostPort(addr)
			return net.DialTimeout(network,
				net.JoinHostPort(serverIP, p), 5*time.Second)
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

// buildWsURL 统一构建 WSS URL。
// fallbackAddr 非空时附加 ?pyip= 激活服务端级别二中转。
func buildWsURL(hostWithPath, port, token, fallbackAddr string) string {
	host := hostWithPath
	path := "/"
	if idx := strings.Index(hostWithPath, "/"); idx != -1 {
		path = hostWithPath[idx:]
		host = hostWithPath[:idx]
	}
	base := fmt.Sprintf("wss://%s:%s%s?token=%s",
		host, port, path, url.QueryEscape(token))
	if fallbackAddr != "" {
		base += "&pyip=" + url.QueryEscape(fallbackAddr)
	}
	return base
}

// ======================== 配置生成 ========================

// GenerateConfigJSON 在内存中生成内核配置 JSON，不落盘。
// s5 参数已删除（v14.2）。
// 所有用户输入字符串统一经 json.Marshal 转义，防止特殊字符破坏 JSON 结构。
func GenerateConfigJSON(
	serverAddr, serverIP, secretKey,
	fallbackAddr, listenAddr,
	strategy, rules string,
) string {
	// 清洗监听地址
	cleanListen := strings.TrimSpace(
		strings.ReplaceAll(strings.ReplaceAll(listenAddr, "\r", ""), "\n", ""),
	)

	// 服务器地址池处理：多种分隔符统一转 ;
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
			poolJSON,     _ := json.Marshal(validPool)
			firstJSON,    _ := json.Marshal(validPool[0])
			strategyJSON, _ := json.Marshal(strategy)
			serverJSON = fmt.Sprintf(
				`"server": %s, "server_pool": %s, "strategy": %s`,
				string(firstJSON), string(poolJSON), string(strategyJSON))
		}
	} else {
		nodeJSON, _ := json.Marshal(strings.TrimSpace(serverAddr))
		serverJSON = fmt.Sprintf(`"server": %s`, string(nodeJSON))
	}

	// 统一用 json.Marshal 转义所有字符串字段
	// [修复] cleanListen 不再裸插，与其他字段保持一致
	listenJSON, _ := json.Marshal(cleanListen)
	tokenJSON,  _ := json.Marshal(secretKey)
	rulesJSON,  _ := json.Marshal(rules)

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

	// 注意：listen 占位符为 %s（无外层引号），因为 json.Marshal 已含引号
	config := fmt.Sprintf(
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
		string(listenJSON),
		serverJSON,
		string(tokenJSON),
		string(rulesJSON),
		serverIPJSON,
		fallbackJSON,
	)

	return config
}

// ======================== 辅助函数 ========================

// pipeDirect 在本地 TCP 连接与 WebSocket 隧道之间做双向数据转发。
// 任意一侧关闭均触发另一侧同步关闭。
func pipeDirect(local net.Conn, ws *websocket.Conn) {
	defer ws.Close()
	defer local.Close()

	// WS → TCP
	go func() {
		buf, ok := bufPool.Get().([]byte)
		if !ok || buf == nil {
			buf = make([]byte, 32*1024)
		}
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

	// TCP → WS
	bufPtr, ok := bufPool.Get().([]byte)
	if !ok || bufPtr == nil {
		bufPtr = make([]byte, 32*1024)
	}
	defer bufPool.Put(bufPtr)

	for {
		n, err := local.Read(bufPtr)
		if n > 0 {
			if werr := ws.WriteMessage(websocket.BinaryMessage, bufPtr[:n]); werr != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
}

// sendNanoHeaderV2 发送 Nano 协议头。
// 格式（v14.2，已移除 s5 字段）：
//
//	┌─────────┬──────┬───────┬─────────┬──────┬─────────┐
//	│hostLen  │host  │port   │fbLen    │fb    │payload  │
//	│1 byte   │N byte│2 byte │1 byte   │M byte│...      │
//	└─────────┴──────┴───────┴─────────┴──────┴─────────┘
//
// 此格式与 Worker parseNano() 完全对齐，P0 Bug 已修复。
func sendNanoHeaderV2(wsConn *websocket.Conn, target string, payload []byte, fb string) error {
	host, portStr, _ := net.SplitHostPort(target)
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	hostBytes := []byte(host)
	fbBytes   := []byte(fb)

	if len(hostBytes) > 255 {
		return errors.New("host length exceeds 255 bytes")
	}
	if len(fbBytes) > 255 {
		return errors.New("fallback address length exceeds 255 bytes")
	}

	buf := new(bytes.Buffer)

	// hostLen + host
	buf.WriteByte(byte(len(hostBytes)))
	buf.Write(hostBytes)

	// port（大端序 2 字节）
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	buf.Write(portBytes)

	// fbLen + fb（s5 字段已删除，此处直接写 fb）
	buf.WriteByte(byte(len(fbBytes)))
	if len(fbBytes) > 0 {
		buf.Write(fbBytes)
	}

	// early data payload
	if len(payload) > 0 {
		buf.Write(payload)
	}

	return wsConn.WriteMessage(websocket.BinaryMessage, buf.Bytes())
}

// handleSOCKS5 完成 SOCKS5 握手并返回目标地址。
// v14.2 修复：所有 IO 调用均检查错误，网络抖动时优雅退出。
func handleSOCKS5(conn net.Conn) (string, error) {
	// 读取认证方法数量
	nMethodsBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, nMethodsBuf); err != nil {
		return "", fmt.Errorf("socks5: read nmethods: %w", err)
	}

	// 跳过认证方法列表
	methods := make([]byte, nMethodsBuf[0])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", fmt.Errorf("socks5: read methods: %w", err)
	}

	// 回复：无需认证
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return "", fmt.Errorf("socks5: write auth response: %w", err)
	}

	// 读取请求头（VER CMD RSV ATYP）
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", fmt.Errorf("socks5: read request header: %w", err)
	}

	var host string
	switch header[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", fmt.Errorf("socks5: read ipv4: %w", err)
		}
		host = net.IP(b).String()
	case 0x03: // 域名
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", fmt.Errorf("socks5: read domain len: %w", err)
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", fmt.Errorf("socks5: read domain: %w", err)
		}
		host = string(domain)
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", fmt.Errorf("socks5: read ipv6: %w", err)
		}
		host = net.IP(b).String()
	default:
		return "", fmt.Errorf("socks5: unsupported address type: %d", header[3])
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", fmt.Errorf("socks5: read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBytes)

	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

// handleHTTP 解析 HTTP 请求（CONNECT 隧道 或 明文 HTTP）并返回目标地址。
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
	req.WriteProxy(&buf)
	return target, buf.Bytes(), 3, nil
}

// parseServerAddr 拆分服务器地址为 host、port、path 三部分。
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
		err  = nil
	}
	return
}






