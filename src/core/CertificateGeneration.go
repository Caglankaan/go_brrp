package core

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"time"
)

type CertificateAuthority struct {
	CA       string
	HostName string
}

func NewCA(CA string, hostName string) *CertificateAuthority {
	if hostName == "" {
		panic("Hostname should not be empty.")
	}
	if CA == "" {
		CA = "rootCA"
	}
	keyPath := CertsPath + CA + ".key"

	_, err := os.Stat(keyPath)

	ca := &CertificateAuthority{
		CA:       CA,
		HostName: hostName,
	}

	if err != nil {
		err := ca.createCACertificate(CertsPath+CA+".pem", CertsPath+CA+".key")
		if err != nil {
			fmt.Println("err: ", err)
			panic(err)
		}
	}

	cert, key, err := ca.loadCert(CertsPath + CA)

	if err != nil {
		fmt.Println("err: ", err)
		panic("err")
	}

	_, err = os.Stat(CertsPath + hostName + ".pem")
	if err != nil {
		err = ca.generateCert(hostName, cert, key)
		if err != nil {
			fmt.Println("err: ", err)
			panic("err")
		}
		// TODO: rootCA.pem should be changed to rootCA.der and we should install it if we get unknown certificate error!!
	}

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

func (ca CertificateAuthority) SSL_CONFIG() *tls.Config {
	cert, err := tls.LoadX509KeyPair(CertsPath+ca.HostName+".pem", CertsPath+ca.HostName+".key")
	if err != nil {
		log.Fatal("Error loading certificate. ", err)
		panic(err)
	}

	return &tls.Config{Certificates: []tls.Certificate{cert}}
}
