package test

import (
	"GoBrrp/core"
	"fmt"
)

func TestCertificateGeneration() {
	var ca *core.CertificateAuthority = core.NewCA("", "test.dev")
	fmt.Println("Created certificate successfuly. CA:", ca)
}
