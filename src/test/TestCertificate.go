package test

import (
	"GoBrrp/core"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
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
	ca.TcpProxy()
}

// func test(){
// 	proxyAddr := "127.0.0.1:443"
// 	serverAddr := "216.239.32.21:443"

// 	// Listen for incoming client connections
// 	listener, err := net.Listen("tcp", proxyAddr)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	defer listener.Close()

// 	for {
// 		// Accept a client connection
// 		clientConn, err := listener.Accept()
// 		if err != nil {
// 			log.Println(err)
// 			continue
// 		}

// 		// Connect to the server

// 		serverConn, err := tls.Dial("tcp", serverAddr, &tls.Config{
// 			InsecureSkipVerify: true,
// 			Certificates:       []tls.Certificate{ca.SSL_CONFIG()},
// 		})
// 		if err != nil {
// 			log.Println(err)
// 			clientConn.Close()
// 			continue
// 		}

// 		// Start a goroutine to proxy data from the client to the server
// 		go proxyData(clientConn, serverConn)

// 		// Start a goroutine to proxy data from the server to the client
// 		go proxyData(serverConn, clientConn)
// 	}
//fmt.Println("Created certificate successfuly. CA:", ca.SSL_CONFIG())
// localAddr := "127.0.0.1:443"
// local, err := net.Listen("tcp", localAddr)
// if err != nil {
// 	log.Fatalf("Failed to listen on %s: %v", localAddr, err)
// }
// defer local.Close()

// log.Printf("Listening on %s", localAddr)

// for {
// 	// Accept incoming client connections.
// 	client, err := local.Accept()
// 	if err != nil {
// 		log.Printf("Failed to accept client connection: %v", err)
// 		continue
// 	}

// 	// Handle the client connection in a new goroutine.
// 	go handleConnection(client, "216.239.32.21:443", ca.SSL_CONFIG())
// }
//}

func proxyData(src, dst net.Conn) {
	defer src.Close()
	defer dst.Close()

	// Copy data from the source to the destination
	_, err := io.Copy(dst, src)
	if err != nil {
		fmt.Println(err)
	}
}
