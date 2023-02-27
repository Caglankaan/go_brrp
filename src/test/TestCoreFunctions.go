package test

import (
	"GoBrrp/core"
	"fmt"
	"net"
	"os"
)

func TestConfigParsingJson() {
	var burrp *core.GoBrrp = core.NewGoBrrp()
	var config core.Config = burrp.Config // access Config field
	config = burrp.ParseConfigJson("config")

	fmt.Println("Config got parsed successfully.")

	fmt.Println(config.Project)
	//fmt.Println(config.Hosts[0].Local)

	fmt.Println("Project: ", config.Project)
	for i, host := range config.Hosts {
		fmt.Printf("Host %d:\n", i+1)
		fmt.Println("  Local:", host.Local)
		fmt.Println("  Original:", host.Original)
		fmt.Println("  CertName:", host.CertName)
		fmt.Println("  Protocol:", host.Protocol)
		fmt.Println("  Script Path:", host.ScriptPath)
		fmt.Println("  Handshake:", host.Handshake)
	}

}
func TestConfigParsing() {
	burrp := core.NewGoBrrp()
	var config map[string]interface{}
	config = burrp.ParseConfig("config")

	fmt.Println("Config got parsed successfully.")

	for k := range config {
		fmt.Println("\"" + k + "\":" + "\"" + config[k].(string) + "\"")
	}

}

func TestSocketCreation() {
	burrp := core.NewGoBrrp()

	socket := burrp.CreateSocketListener("udp", "192.168.35.1:7771")

	ln, err := net.FileListener(os.NewFile(uintptr(socket), ""))
	if err != nil {
		panic(err)
	}

	defer ln.Close()

	// accept incoming connections and handle them
	for {
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			fmt.Println("Error reading:", err.Error())
			return
		}
		fmt.Println("Received data:", string(buf[:n]))
		// handle the connection
		// ...
	}

	// // start listening on the socket
	// if err := syscall.Listen(socket, 10); err != nil {
	// 	panic(err)
	// }

	// // accept incoming connections and handle them
	// for {
	// 	conn, err := net.FileConn(os.NewFile(uintptr(socket), ""))

	// 	if err != nil {
	// 		panic(err)
	// 	}

	// 	buf := make([]byte, 1024)
	// 	n, err := conn.Read(buf)
	// 	if err != nil {
	// 		fmt.Println("Error reading:", err.Error())
	// 		return
	// 	}
	// 	fmt.Println("Received data:", string(buf[:n]))
	// }
}
