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
