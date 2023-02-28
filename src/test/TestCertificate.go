package test

import (
	"GoBrrp/core"
	"GoBrrp/helper"
	"crypto/tls"
	"io"
	"log"
	"net"

	"github.com/sirupsen/logrus"
)

func handleConnection(client net.Conn, remoteAddr string, cert tls.Certificate) {
	defer client.Close()

	// Connect to the remote server.
	remote, err := tls.Dial("tcp", remoteAddr, &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		log.Printf("Failed to connect to %s: %v", remoteAddr, err)
		return
	}
	defer remote.Close()

	log.Printf("Proxying from %s to %s", client.RemoteAddr(), remoteAddr)

	// Copy data between the client and the remote server bidirectionally.
	go func() {
		if _, err := io.Copy(remote, client); err != nil {
			log.Printf("Error copying data from client to remote: %v", err)
		}
	}()

	if _, err := io.Copy(client, remote); err != nil {
		log.Printf("Error copying data from remote to client: %v", err)
	}
}
func TestCertificateGeneration() {
	var burrp *core.GoBrrp = core.NewGoBrrp()
	var config core.Config = burrp.Config // access Config field
	config = burrp.ParseConfigJson("config")
	var ca *core.CertificateAuthority = core.NewCA("", "go.dev", config.Hosts[0])
	helper.MakeLogger(config.LogPath, config.LogLevel)

	//helper.Logger.Debugln("???? allah askina")
	logrus.Debug("soo wtf2 ?")
	ca.TcpProxy()
}
