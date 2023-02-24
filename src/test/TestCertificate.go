package test

import (
	"GoBrrp/core"
	"fmt"
	"os"
)

func TestCertificateGeneration() {
	keyPath := core.CertsPath + "rootCA.key"
	_, err := os.Stat(keyPath)
	if err == nil {
		// TODO: continue
		fmt.Println("Path exist")
	} else {
		err := core.CreateCACertificate(core.CertsPath+"rootCA.pem", core.CertsPath+"rootCA.key")
		if err != nil {
			fmt.Println("err: ", err)
		}
	}

	cert, key, err := core.LoadCert(core.CertsPath + "rootCA")
	example_host := "go.dev"

	_, err = os.Stat(core.CertsPath + example_host + ".pem")
	if err == nil {
		fmt.Println("Cert path exist")
	} else {

		err = core.GenerateCert(example_host, cert, key)
		if err != nil {
			fmt.Println("err: ", err)
		}

		// TODO: rootCA.pem should be changed to rootCA.der and we should install it if we get unknown certificate error!!
	}

}
