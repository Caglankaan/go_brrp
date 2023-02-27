package main

import (
	"GoBrrp/test"
)

func main() {
	test.TestCertificateGeneration()
	test.TestConfigParsing()
	test.TestConfigParsingJson()
	//test.TestSocketCreation()
}
