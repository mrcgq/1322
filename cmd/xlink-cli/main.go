

// main.go
// Xlink CLI Entry Point v15.0 (Lean Edition)
// CLI接口保持与客户端完全兼容：
//   --s5 flag保留（客户端传参），但不再传入Nano协议头（服务端不使用）
//   --strategy flag保留（客户端传参），内核固定使用Random，忽略此参数
//   --rules flag保留，正常透传

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
	// 强制开启纯Go DNS解析器，绕过Windows getaddrinfow
	os.Setenv("GODEBUG", "netdns=go")

	serverAddr  := flag.String("server",   "",                  "Server address (single or pool, one per line or ';' separated)")
	serverIP    := flag.String("ip",       "",                  "Specific server IP override")
	secretKey   := flag.String("key",      "",                  "Secret key / token")
	fallbackAddr := flag.String("fallback", "",                 "Fallback relay IP for Worker outbound")
	listenAddr  := flag.String("listen",   "127.0.0.1:10808",   "Local SOCKS5 listen address")
	rules       := flag.String("rules",    "",                  "Routing rules (keyword,node per line)")

	// 以下两个flag仅为保持与客户端CLI调用的兼容性，内核不再使用
	_ = flag.String("s5",       "", "(reserved, unused in v15.0)")
	_ = flag.String("strategy", "random", "(reserved, always random in v15.0)")

	flag.Parse()

	if *serverAddr == "" {
		log.Fatal("[CLI] Error: --server is required.")
	}

	configJSON := core.GenerateConfigJSON(
		*serverAddr,
		*serverIP,
		*secretKey,
		*fallbackAddr,
		*listenAddr,
		*rules,
	)

	log.Println("[CLI] Starting Xlink Lean Kernel v15.0...")

	listener, err := core.StartInstance([]byte(configJSON))
	if err != nil {
		log.Fatalf("[CLI] Failed to start: %v", err)
	}

	log.Printf("[CLI] Engine running on %s", *listenAddr)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	if listener != nil {
		listener.Close()
	}
}





