package main

import (
	"fmt"
	flags "github.com/jessevdk/go-flags"
	"github.com/rorycl/sshagentca/util"
	"golang.org/x/crypto/ssh/terminal"
	"net"
	"os"
)

const VERSION = "0.0.3-beta"
const usage = `<options> <yamlfile>

SSH Agent CA version %s

A proof-of-concept SSH server forwarded agent certificate authority

    sshagentca -h
    sshagentca -p <privatekey> -c <caprivatekey> -a <authorized_keys>
               -i <ipaddress> -p <port> settings.yaml

Application Arguments:


 `

// flag options
type Options struct {
	PrivateKey     string `short:"t" long:"privateKey" required:"true" description:"server ssh private key (password protected)"`
	CAPrivateKey   string `short:"c" long:"caPrivateKey" required:"true" description:"certificate authority private key (password protected)"`
	AuthorizedKeys string `short:"a" long:"authorizedKeys" required:"true" description:"authorized keys file with at least one entry"`
	IPAddress      string `short:"i" long:"ipAddress" default:"0.0.0.0" description:"ipaddress"`
	Port           string `short:"p" long:"port" default:"2222" description:"port"`
	Args           struct {
		YamlFile string `description:"settings yaml file"`
	} `positional-args:"yes" required:"yes"`
}

func hardexit(msg string) {
	fmt.Printf("\n\n> %s\n\nAborting startup.\n", msg)
	os.Exit(1)
}

func main() {

	var options Options
	var parser = flags.NewParser(&options, flags.Default)
	parser.Usage = fmt.Sprintf(usage, VERSION)

	if _, err := parser.Parse(); err != nil {
		os.Exit(1)
	}

	fmt.Println("SSH Agent CA")

	// load server private key
	fmt.Printf("\nServer private key password: ")
	pvtPW, err := terminal.ReadPassword(0)
	if err != nil {
		hardexit(fmt.Sprintf("Could not read password: %s", err))
	}
	privateKey, err := util.LoadPrivateKeyWithPassword(options.PrivateKey, pvtPW)
	if err != nil {
		hardexit(fmt.Sprintf("Private key could not be loaded, %s", err))
	}

	// load certificate authority private key
	fmt.Printf("\nCertificate Authority private key password: ")
	caPW, err := terminal.ReadPassword(0)
	if err != nil {
		hardexit(fmt.Sprintf("Could not read password: %s", err))
	}
	caKey, err := util.LoadPrivateKeyWithPassword(options.CAPrivateKey, caPW)
	if err != nil {
		hardexit(fmt.Sprintf("CA Private key could not be loaded, %s", err))
	}

	// load settings and authorized keys
	settings, err := util.SettingsLoad(options.Args.YamlFile, options.AuthorizedKeys)
	if err != nil {
		hardexit(fmt.Sprintf("Settings could not be loaded : %s", err))
	}

	// check ip
	if net.IP(options.IPAddress) == nil {
		hardexit(fmt.Sprintf("Invalid ip address %s", options.IPAddress))
	}

	Serve(options, privateKey, caKey, settings)
}
