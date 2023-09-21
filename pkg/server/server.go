package server

import (
	"fmt"
	"io/fs"
	"os"

	"github.com/multisig-labs/webauthn-demo/pkg/config"
	"github.com/multisig-labs/webauthn-demo/pkg/handler"
)

func StartServer(host string, port int, db string, webContent fs.FS) {
	listenAddr := fmt.Sprintf("%s:%d", host, port)

	// Basically "cd" into the /public folder of the embedded content
	var err error
	if webContent, err = fs.Sub(webContent, "public"); err != nil {
		panic(err)
	}

	if config.Env.DevMode {
		fmt.Println("Ignoring embedded content, serving from /public")
		webContent = os.DirFS("./public")
	}

	fmt.Printf("\n\nNavigate to: http://%s/home\n\n", listenAddr)

	router := handler.NewRouter(db, webContent)
	router.Logger.Fatal(router.Start(listenAddr))
}
