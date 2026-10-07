//文件三：main.go (Go CLI 入口)

// =========================================================================================
// main.go
// Xlink Odyssey CLI Entrance v14.0 (S-Tier Industrial Edition)
// [特性] 专有 --pipe-stdin 内存流模式，彻底杜绝命令行明文泄露凭据
// [生命周期] 支持父进程管道消亡自收敛与操作系统信号（SIGINT / SIGTERM / Break）平滑断开
// =========================================================================================

package main

import (
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/mrcgq/xy/core"
)

func main() {
	// 强制使用纯 Go DNS 解析器，消除 CGO 依赖并在 Windows 平台实现无损并发解析
	_ = os.Setenv("GODEBUG", "netdns=go")

	pipeMode := flag.Bool("pipe-stdin", false, "Read JSON configuration securely from STDIN stream")
	flag.Parse()

	var configJSON []byte
	var err error

	if *pipeMode {
		// 从标准输入匿名安全流中一次性载入内存，系统进程树中 0 敏感参数暴露
		configJSON, err = io.ReadAll(os.Stdin)
		if err != nil || len(configJSON) == 0 {
			core.EmitError("Stdin 管道配置流为空或读取异常")
			os.Exit(1)
		}
	} else {
		core.EmitError("错误: 传统明文 CLI 参数启动已被安全阻断，请使用 --pipe-stdin 模式")
		log.Fatal("[Fatal] Direct CLI parameter mode is deprecated for security. Use --pipe-stdin.")
	}

	// 启动内核实例并获取监听器句柄
	listener, err := core.StartInstance(configJSON)
	if err != nil {
		os.Exit(1)
	}

	// 捕获系统退出与终端中断信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	// 阻塞等待系统中断信号
	<-sigChan

	// 触发显式平滑关闭流程
	if listener != nil {
		_ = listener.Close()
	}
}





