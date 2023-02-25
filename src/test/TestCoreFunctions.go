package test

import (
	"GoBrrp/core"
	"fmt"
)

func TestConfigParsing() {
	burrp := core.New()
	var config map[string]interface{}
	config = burrp.ParseConfig("config")

	fmt.Println("Config got parsed successfully.")

	for k := range config {
		fmt.Println("\"" + k + "\":" + "\"" + config[k].(string) + "\"")
	}

}

func TestSocketCreation() {
	burrp := core.New()
	burrp.CreateSocketListener("tcp", "34.74.100.4:8082")
}
