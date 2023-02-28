package core

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
)

var (
	f, _        = os.Getwd()
	Basepath    = filepath.Dir(f)
	ConfigsPath = Basepath + "\\src\\configs\\"
	CertsPath   = Basepath + "\\src\\certs\\"
)

type HostConfig struct {
	Local      string `json:"local"`
	Original   string `json:"original"`
	HostName   string `json:"host_name"`
	Protocol   string `json:"protocol"`
	ScriptPath string `json:"script_path"`
	Handshake  bool   `json:"handshake"`
}

type Config struct {
	Project  string       `json:"Project"`
	LogPath  string       `json:"log_path"`
	LogLevel string       `json:"log_level"`
	Hosts    []HostConfig `json:"Hosts"`
}

type GoBrrp struct {
	not_started   bool
	asked_to_quit bool
	is_stopped    bool
	Config        Config
}

func NewGoBrrp() *GoBrrp {
	b := &GoBrrp{
		not_started:   true,
		asked_to_quit: false,
		is_stopped:    false,
	}

	return b
}

func (brrp GoBrrp) ParseConfig(ConfigName string) map[string]interface{} {
	fields := strings.Split(ConfigName, ".")
	if len(fields) < 2 {
		ConfigName += ".yaml"
	}

	data, err := ioutil.ReadFile(ConfigsPath + ConfigName)
	if err != nil {
		fmt.Println(err)
	}

	var config map[string]interface{}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		fmt.Println(err)
	}

	return config
}

func (brrp GoBrrp) ParseConfigJson(ConfigName string) Config {
	fields := strings.Split(ConfigName, ".")
	if len(fields) < 2 {
		ConfigName += ".json"
	}

	data, err := ioutil.ReadFile(ConfigsPath + ConfigName)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}

	var config Config

	err = json.Unmarshal(data, &config)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}

	return config
}

func (brrp GoBrrp) resolveIp(network string, address string) (net.IP, int) {
	if network == "udp" {
		result, err := net.ResolveUDPAddr(network, address)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}

		return result.IP, result.Port
	} else {
		result, err := net.ResolveTCPAddr(network, address)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}

		return result.IP, result.Port
	}
}

func (brrp GoBrrp) CreateSocketListener(SocketType string, ListenAddress string) syscall.Handle {
	AVAILABLE_SOCKET_TYPES := map[string][2]int{
		"tcp": {syscall.SOCK_STREAM, syscall.IPPROTO_TCP},
		"udp": {syscall.SOCK_DGRAM, syscall.IPPROTO_UDP},
	}

	SocketType = strings.ToLower(SocketType)

	selectedSocketType := AVAILABLE_SOCKET_TYPES[SocketType][0]
	selectedProtocolType := AVAILABLE_SOCKET_TYPES[SocketType][1]

	if selectedSocketType == 0 {
		fmt.Println("Invalid socket type provided.")
		return syscall.InvalidHandle
	}

	s, err := syscall.Socket(syscall.AF_INET, selectedSocketType, selectedProtocolType)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}

	err = syscall.SetsockoptInt(s, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}

	ip, port := brrp.resolveIp(SocketType, ListenAddress)

	sa := &syscall.SockaddrInet4{
		Port: port,
		Addr: [4]byte{ip[0], ip[1], ip[2], ip[3]},
	}

	syscall.Bind(s, sa)

	return s
}
