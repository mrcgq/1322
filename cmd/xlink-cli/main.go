
// =========================================================================================
// main.go
// Xlink Odyssey CLI 入口 v14.2
// [变更] 删除 --s5 flag，移除 socks5Addr 传递
// =========================================================================================

package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/mrcgq/xy/core"
)

func main() {
	// 强制使用纯 Go DNS 解析器，避免 CGO 解析器在某些系统上的问题
	os.Setenv("GODEBUG", "netdns=go")

	serverAddr  := flag.String("server",   "",                 "Server address (single or pool separated by ';')")
	serverIP    := flag.String("ip",       "",                 "Specific server IP override")
	secretKey   := flag.String("key",      "",                 "Secret key / token")
	fallbackAddr := flag.String("fallback", "",                "Fallback relay IP (passed to Worker as Nano fb field + ?pyip=)")
	listenAddr  := flag.String("listen",   "127.0.0.1:10808", "Local SOCKS5 listen address")
	strategy    := flag.String("strategy", "random",           "Load balance strategy: random | rr | hash")
	rules       := flag.String("rules",    "",                 "Routing rules string (keyword,node separated by '|')")
	// --s5 flag 已删除（v14.2）

	flag.Parse()

	if *serverAddr == "" {
		log.Fatal("[CLI] Error: --server argument is required.")
	}

	// 验证监听地址格式
	if _, _, err := net.SplitHostPort(*listenAddr); err != nil {
		log.Fatalf("[CLI] Error: invalid --listen address '%s': %v", *listenAddr, err)
	}

	// 生成内存配置（不含 s5）
	configJSON := core.GenerateConfigJSON(
		*serverAddr,
		*serverIP,
		*secretKey,
		*fallbackAddr,
		*listenAddr,
		*strategy,
		*rules,
	)

	log.Println("[CLI] Starting X-Link Odyssey Kernel (v14.2)...")
	log.Printf("[CLI] Listen: %s | Strategy: %s", *listenAddr, *strategy)

	listener, err := core.StartInstance([]byte(configJSON))
	if err != nil {
		log.Fatalf("[CLI] Failed to start core engine: %v", err)
	}

	log.Printf("[CLI] Engine running successfully on %s", *listenAddr)

	// 等待系统信号优雅退出
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[CLI] Shutting down...")
	if listener != nil {
		listener.Close()
	}
	log.Println("[CLI] Stopped.")
}
