

package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"github.com/mrcgq/xy/core" 
)

func main() {
	// 核心修复：强制开启纯 Go DNS/端口解析器，彻底绕过 Windows 损坏的 getaddrinfow 接口
	os.Setenv("GODEBUG", "netdns=go")

	serverAddr := flag.String("server", "", "Server address (single or pool separated by ';')")
	serverIP := flag.String("ip", "", "Specific server IP")
	secretKey := flag.String("key", "", "Secret key")
	socks5Addr := flag.String("s5", "", "SOCKS5 proxy address")
	fallbackAddr := flag.String("fallback", "", "Fallback address")
	listenAddr := flag.String("listen", "127.0.0.1:10808", "Local listen address")
	strategy := flag.String("strategy", "random", "Load balance strategy: random, rr, hash")
	rules := flag.String("rules", "", "Routing rules string")

	flag.Parse()

	if *serverAddr == "" {
		log.Fatal("[CLI] Error: --server argument is required.")
	}

	// 在内存中生成配置 JSON，不落地磁盘，避免随机磁盘 I/O 带来的延迟税 [1, 2]
	configJSON := core.GenerateConfigJSON(*serverAddr, *serverIP, *secretKey, *socks5Addr, *fallbackAddr, *listenAddr, *strategy, *rules)
	
	log.Println("[CLI] Starting X-Link Odyssey Kernel (v13.1)...")

	listener, err := core.StartInstance([]byte(configJSON))
	if err != nil {
		log.Fatalf("[CLI] Failed to start core engine: %v", err)
	}
	
	log.Printf("[CLI] Engine running successfully on %s", *listenAddr)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	if listener != nil {
		listener.Close()
	}
}

