package core

import (
	"GoBrrp/helper"
	"GoBrrp/processing"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"github.com/sirupsen/logrus"
)

type CertificateAuthority struct {
	CA         string
	HostName   string
	Hostconfig HostConfig
}

func NewCA(CA string, hostName string, config HostConfig) *CertificateAuthority {
	if hostName == "" {
		panic("Hostname should not be empty.")
	}
	if CA == "" {
		CA = "rootCA"
	}
	keyPath := CertsPath + CA + ".key"

	_, err := os.Stat(keyPath)

	ca := &CertificateAuthority{
		CA:         CA,
		HostName:   hostName,
		Hostconfig: config,
	}

	if err != nil {
		err := ca.createCACertificate(CertsPath+CA+".pem", CertsPath+CA+".key")
		if err != nil {
			logrus.Debugln("err: ", err)
			panic(err)
		}
	}

	cert, key, err := ca.loadCert(CertsPath + CA)

	if err != nil {
		logrus.Debugln("err: ", err)
		panic("err")
	}

	_, err = os.Stat(CertsPath + hostName + ".pem")
	if err != nil {
		err = ca.generateCert(hostName, cert, key)
		if err != nil {
			logrus.Debugln("err: ", err)
			panic("err")
		}
		// TODO: rootCA.pem should be changed to rootCA.der and we should install it if we get unknown certificate error!!
	}

	//compilePath(ca.Hostconfig)

	return ca
}
func (ca CertificateAuthority) generateRandomBigInt(numBits int) (*big.Int, error) {
	// Generate a random byte slice with the specified number of bits
	numBytes := (numBits + 7) / 8
	bytes := make([]byte, numBytes)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}

	result := new(big.Int).SetBytes(bytes)

	result.SetBit(result, numBits, 1)
	return result, nil
}

func (ca CertificateAuthority) hashPublicKey(pub *rsa.PublicKey) []byte {
	derBytes, _ := x509.MarshalPKIXPublicKey(pub)
	hash := sha1.Sum(derBytes)
	return hash[:]
}

func (ca CertificateAuthority) createCACertificate(certFile string, keyFile string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	subject := pkix.Name{
		CommonName: "My Root CA",
	}

	serialBigInt, err := ca.generateRandomBigInt(25)
	template := x509.Certificate{
		SerialNumber:          serialBigInt,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // Valid for 10 years
		SubjectKeyId:          ca.hashPublicKey(&priv.PublicKey),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
	}
	template.AuthorityKeyId = template.SubjectKeyId

	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	keyOut, err := os.Create(keyFile)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	if err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return err
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	return nil
}

func (ca CertificateAuthority) loadCert(name string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Load certificate file
	cf, err := os.Open(name + ".pem")
	if err != nil {
		return nil, nil, err
	}
	defer cf.Close()
	certBytes, err := io.ReadAll(cf)
	if err != nil {
		return nil, nil, err
	}
	certBlock, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	// Load private key file
	kf, err := os.Open(name + ".key")
	if err != nil {
		return nil, nil, err
	}
	defer kf.Close()
	keyBytes, err := io.ReadAll(kf)
	if err != nil {
		return nil, nil, err
	}
	keyBlock, _ := pem.Decode(keyBytes)
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func (ca CertificateAuthority) generateCert(hostname string, caCert *x509.Certificate, caKey *rsa.PrivateKey) error {
	// Generate a new RSA key pair
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Create a new X.509 certificate template
	serialBigInt, err := ca.generateRandomBigInt(25)
	template := &x509.Certificate{
		SerialNumber: serialBigInt,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		SubjectKeyId:          ca.hashPublicKey(&priv.PublicKey),
		AuthorityKeyId:        caCert.SubjectKeyId,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:              []string{hostname},
		IsCA:                  false,
	}

	// Sign the certificate with the CA certificate and private key
	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, priv.Public(), caKey)
	if err != nil {
		return err
	}

	// Write the certificate and private key to files
	certOut, err := os.Create(CertsPath + hostname + ".pem")
	if err != nil {
		return err
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	keyOut, err := os.OpenFile(CertsPath+hostname+".key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return nil
}

func (ca CertificateAuthority) SSL_CONFIG() tls.Certificate {
	cert, err := tls.LoadX509KeyPair(CertsPath+ca.HostName+".pem", CertsPath+ca.HostName+".key")
	if err != nil {
		log.Fatal("Error loading certificate. ", err)
		panic(err)
	}
	//https://gist.github.com/denji/12b3a568f092ab951456
	return cert //tls.Config{Certificates: []tls.Certificate{cert}}
}

func (ca CertificateAuthority) TcpProxy() {
	//toProxyListener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ca.Hostconfig.Local, config.Port))
	//clients := []string{}

	var clients = make(map[string]bool)

	toProxyListener, err := net.Listen("tcp", ca.Hostconfig.Local)
	if err != nil {
		panic(err)
	}
	//defer toProxyListener.Close()

	logrus.Debugln(ca.Hostconfig.Protocol, "Proxy Listens at ", ca.Hostconfig.Local)

	for true {
		client, err := toProxyListener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			panic(err)
		}

		go func(client net.Conn) {
			//defer client.Close()

			_, port, _ := net.SplitHostPort(client.RemoteAddr().String())
			logrus.Debugln("client.RemoteAddr().String(): ", client.RemoteAddr().String())

			if _, ok := clients[port]; !ok {
				clients[port] = true

				toServerConn, err := net.DialTimeout("tcp", ca.Hostconfig.Original, 10*time.Second)
				if err != nil {
					logrus.Debugln("failed to connect to remote server: %s\n", err)
					return
				}
				//defer toServerConn.Close()

				toProxySSLSocket, toServerConn, err := ca.ssl_tls_handshake(client, toServerConn)
				if err != nil {
					logrus.Debugln("Err is: ", err)
					panic(err)
				}

				// config.Processor.PassEvent(Events{
				// 	Type: EventsNetClientConnected,
				// 	Data: map[string]interface{}{
				// 		"c2p_socket": toProxySSLSocket,
				// 		"p2s_socket": toServerConn,
				// 		"config":     config,
				// 	},
				// })

				//toProxySSLSocket.SetDeadline(time.Now().Add(5 * time.Second))
				//toServerConn.SetDeadline(time.Now().Add(5 * time.Second))

				go connectionHandler(toProxySSLSocket, toServerConn, true)
				go connectionHandler(toServerConn, toProxySSLSocket, false)
				//go clientHandler(toProxySSLSocket, toServerConn)
			}
		}(client)
	}
}

func compilePath(config HostConfig) {
	//Here is for DLL, dll is not working??

	// if config.CompileSO {
	// 	parts = strings.Split(config.ScriptPath, ":")
	// 	sourcePath := Basepath + parts[0]
	// 	binaryPath = Basepath + strings.Replace(parts[0], ".go", ".dll", -1)
	// 	logrus.Debugln("binary path: ", binaryPath)
	// 	logrus.Debugln("sourcePath path: ", sourcePath)

	// 	cmd := exec.Command("go", "build", "-o", binaryPath, "-buildmode=c-shared", sourcePath)
	// 	err := cmd.Run()

	// 	if err != nil {
	// 		logrus.Debugln("Error compiling plugin: %v\n", err)
	// 		return
	// 	}

	// 	logrus.Debugln("Plugin compiled successfully to %s\n", binaryPath)
	// }

	//Here is for Exe
	// if config.CompileSO {
	// 	parts = strings.Split(config.ScriptPath, ":")
	// 	sourcePath := Basepath + parts[0]
	// 	binaryPath = Basepath + strings.Replace(parts[0], ".go", ".exe", -1)
	// 	logrus.Debugln("binary path: ", binaryPath)
	// 	logrus.Debugln("sourcePath path: ", sourcePath)

	// 	cmd := exec.Command("go", "build", "-o", binaryPath, sourcePath)
	// 	err := cmd.Run()

	// 	if err != nil {
	// 		logrus.Debugln("Error compiling plugin: %v\n", err)
	// 		return
	// 	}

	// 	logrus.Debugln("Plugin compiled successfully to %s\n", binaryPath)
	// 	logrus.Debugln("runExeExample(binaryPath, true): ", runExeExample(binaryPath, true))
	// }
}

func runExeExample(binaryPath string, inner bool) []byte {
	x := []byte("This is my test")
	cmd := exec.Command(binaryPath, strconv.FormatBool(inner), string(x))

	// Run the command and get the output
	output, err := cmd.Output()
	if err != nil {
		logrus.Debugln(err.Error())
		panic(err)
	}

	// Print the output
	//logrus.Debugln("output is: ", string(output))
	return output
}

// TODO: its not working, why?
func runDllExample(binaryPath string) []byte {
	dll, err := syscall.LoadDLL(binaryPath)
	if err != nil {
		panic(err)
	}
	defer dll.Release()

	proc, err := dll.FindProc("inner")
	if err != nil {
		panic(err)
	}

	innerFunc := *(*func([]byte) []byte)(unsafe.Pointer(&proc))

	result := innerFunc([]byte("test"))
	logrus.Debugln(string(result))
	return result
}

func readConn(conn net.Conn) <-chan []byte {
	ch := make(chan []byte)
	go func() {
		buffer := make([]byte, 640000)
		n, err := conn.Read(buffer)
		if err != nil {
			logrus.Debugln("err: ", err)
			return
		}
		ch <- buffer[:n]
	}()
	return ch
}

func connectionHandler(IncomingSocket net.Conn, OutgoingSocket net.Conn, incoming bool) {
	for {
		data := make([]byte, 640000)
		n, err := IncomingSocket.Read(data)
		// if err != nil || n == 0 {
		// 	//closeToProxySocket = true
		// 	logrus.Debugln("Err is not nil. Err: ", err)
		// 	//break
		// }

		//TODO: play with data

		if err == nil {
			new_data := []byte{}

			if incoming {
				new_data = processing.Inner(data[:n])
			} else {
				new_data = processing.Outer(data[:n])
			}

			logrus.Debugln("new_data: ", helper.PrintByteArray(new_data))

			_, err = OutgoingSocket.Write(new_data)
			if err != nil {
				logrus.Debugln("err: ", err)
				return
			}
		}
	}
}

func clientHandler(toProxySocket net.Conn, toServerSocket net.Conn) {
	// go connectionHandler(toProxySocket, toServerSocket)

	// go connectionHandler(toServerSocket, toProxySocket)

	// //var closeToProxySocket bool
	// for {
	// 	// select {
	// 	// case <-askedToQuit:
	// 	// 	return
	// 	// default:
	// 	//readSet := []net.Conn{toProxySocket, toServerSocket}
	// 	//writeSet := []net.Conn{}
	// 	//_, err := netutil.Poll(readSet, writeSet, time.Second)
	// 	// if err != nil {
	// 	// 	return
	// 	// }
	// 	//readable, _, _ := selectChannels([]net.Conn{toProxySocket, toServerSocket}, nil, nil, 5*time.Second)
	// 	// if true {

	// 	// 	data := make([]byte, 640000)
	// 	// 	_, err := toServerSocket.Read(data)
	// 	// 	if err != nil {
	// 	// 		logrus.Debugln("Error reading data from server socket: ", err)
	// 	// 		break
	// 	// 	}
	// 	// 	toProxySocket.Write(data)
	// 	// }
	// 	// select {
	// 	// case data := <-readConn(toProxySocket):
	// 	data1 := make([]byte, 640000)
	// 	n, err := toProxySocket.Read(data1)
	// 	if err != nil || n == 0 {
	// 		//closeToProxySocket = true
	// 		logrus.Debugln("closetoproxysocket broken. Err: ", err)
	// 		break
	// 	}
	// 	//TODO: play with data
	// 	logrus.Debugln("data1: ", ByteArrayToString(data1[:n]))
	// 	_, err = toServerSocket.Write(data1[:n])
	// 	if err != nil {
	// 		logrus.Debugln("err: ", err)
	// 		return
	// 	}
	// 	//case data := <-readConn(toServerSocket):
	// 	logrus.Debugln("toserversocket if?")
	// 	data2 := make([]byte, 640000)
	// 	n, err = toServerSocket.Read(data2)
	// 	if err != nil || n == 0 {
	// 		//closeToProxySocket = true
	// 		logrus.Debugln("toServerSocket broken. Err: ", err)
	// 		break
	// 	}
	// 	logrus.Debugln("data2: ", ByteArrayToString(data2[:n]))
	// 	//TODO: play with data

	// 	_, err = toProxySocket.Write(data2[:n])
	// 	if err != nil {
	// 		logrus.Debugln("err: ", err)
	// 		return
	// 	}

	// 	// case <-time.After(1 * time.Second):
	// 	// 	logrus.Debugln("Timeout reached")
	// 	// 	return
	// 	// }
	// }

}

func containsConn(conns []net.Conn, c net.Conn) bool {
	for _, conn := range conns {
		if conn == c {
			return true
		}
	}
	return false
}

func (ca CertificateAuthority) ssl_tls_handshake(toProxySocket net.Conn, toServerSocket net.Conn) (net.Conn, net.Conn, error) {
	if !ca.Hostconfig.Handshake { // && !config.clientEncryption {
		return toProxySocket, toServerSocket, nil
	}

	// packet := make([]byte, 4096)
	// toProxySocket.SetReadDeadline(time.Now().Add(time.Second))
	// _, err := toProxySocket.Read(packet)
	// if err != nil {
	// 	logrus.Debugln("so error?")
	// 	panic(err)
	// 	return toProxySocket, toServerSocket, err
	// }

	// if packet[0] != 0x16 || packet[1] != 0x03 {
	// 	return toProxySocket, toServerSocket, nil
	// }
	// logrus.Debugln("So wtf happened: ", packet)

	if ca.Hostconfig.Handshake {
		tlsConfig := &tls.Config{
			MinVersion:         tls.VersionTLS12,
			Certificates:       []tls.Certificate{ca.SSL_CONFIG()},
			InsecureSkipVerify: true,
		}

		// cert := ca.SSL_CONFIG()
		// tlsConfig.Certificates = append(tlsConfig.Certificates, cert)

		toProxySocket = tls.Server(toProxySocket, tlsConfig)
	}

	tlsConfig := &tls.Config{
		ServerName:         ca.Hostconfig.HostName,
		InsecureSkipVerify: true,
	}

	toServerSocket = tls.Client(toServerSocket, tlsConfig)
	return toProxySocket, toServerSocket, nil
}
