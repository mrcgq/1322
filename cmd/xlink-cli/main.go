package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mrcgq/xy/core"
)

func main() {
	configPath := flag.String("c", "", "Path to config file (JSON)")
	ping       := flag.Bool("ping", false, "Enable ping mode")
	server     := flag.String("server", "", "Server address for ping mode")
	key        := flag.String("key", "", "Secret key for ping mode (format: token|fallback)")
	ip         := flag.String("ip", "", "Global IP for ping mode")

	flag.Parse()

	// ── Ping 模式 ──────────────────────────────────────────
	if *ping {
		log.Println("Starting Ping Test Mode...")
		if *server == "" || *key == "" {
			log.Fatalf("Error: --server and --key are required for ping mode.")
		}
		// ping 模式只需要 secretKey 部分，去掉 fallback
		secretKey := strings.SplitN(*key, "|", 2)[0]
		core.RunSpeedTest(*server, secretKey, *ip)
		return
	}

	// ── 代理模式 ───────────────────────────────────────────
	if *configPath == "" {
		log.Fatalf("Error: Config file path is required. Use -c <path_to_config.json>")
	}

	configBytes, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("Failed to read config file '%s': %v", *configPath, err)
	}

	listener, err := core.StartInstance(configBytes)
	if err != nil {
		log.Fatalf("Failed to start instance: %v", err)
	}

	log.Println("Xlink Kernel is running. Press Ctrl+C to exit.")

	// 优雅退出：捕获信号后正确清理所有资源
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down...")
	core.StopInstance(listener) // ✅ 正确关闭：同时停止 maintenance goroutine
}
