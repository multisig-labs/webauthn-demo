package main

import (
	"embed"
	"flag"
	"fmt"
	"os"

	"runtime/debug"

	"github.com/jxskiss/mcli"
	"github.com/multisig-labs/webauthn-demo/pkg/server"
	"github.com/multisig-labs/webauthn-demo/pkg/version"
)

//go:embed public/*
var webContent embed.FS

func main() {
	defer handlePanic()
	mcli.Add("serve", serveCmd, "Start HTTP server")
	mcli.AddHelp()
	mcli.AddCompletion()
	mcli.Run()
}

func serveCmd() {
	args := struct {
		Host string `cli:"--host, host" default:"0.0.0.0"`
		Port int    `cli:"--port, port" default:"8000"`
		Db   string `cli:"--db, database" default:"data/webauthn.db"`
	}{}
	mcli.Parse(&args, mcli.WithErrorHandling(flag.ExitOnError))

	server.StartServer(args.Host, args.Port, args.Db, webContent)
}

func handlePanic() {
	if panicPayload := recover(); panicPayload != nil {
		stack := string(debug.Stack())
		fmt.Fprintln(os.Stderr, "================================================================================")
		fmt.Fprintln(os.Stderr, "            Fatal error. Sorry! You found a bug.")
		fmt.Fprintln(os.Stderr, "================================================================================")
		fmt.Fprintf(os.Stderr, "Version:           %s\n", version.Version)
		fmt.Fprintf(os.Stderr, "Build Date:        %s\n", version.BuildDate)
		fmt.Fprintf(os.Stderr, "Git Commit:        %s\n", version.GitCommit)
		fmt.Fprintf(os.Stderr, "Go Version:        %s\n", version.GoVersion)
		fmt.Fprintf(os.Stderr, "OS / Arch:         %s\n", version.OsArch)
		fmt.Fprintf(os.Stderr, "Panic:             %s\n\n", panicPayload)
		fmt.Fprintln(os.Stderr, stack)
		os.Exit(1)
	}
}
