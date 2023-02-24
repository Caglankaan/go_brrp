package core

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	f, _     = os.Getwd()
	Basepath = filepath.Dir(f)
)

var ConfigsPath = Basepath + "\\src\\configs\\"
var CertsPath = Basepath + "\\src\\certs\\"

type GoBrrp struct {
	not_started   bool
	asked_to_quit bool
	is_stopped    bool
}

func New() *GoBrrp {
	b := new(GoBrrp)

	b.not_started = true
	b.asked_to_quit = false
	b.is_stopped = false

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
