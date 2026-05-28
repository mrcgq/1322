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
	configPath := flag.String("c", "", "Path to config file (JSON)")
	flag.Parse()

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

	// 优雅退出：捕获信号后正确关闭 listener
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down...")
	listener.Close()
}
