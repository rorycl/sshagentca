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

func main() {

	var options util.Options
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
		panic(fmt.Errorf("Could not read password: %s", err))
	}
	privateKey, err := util.LoadPrivateKeyWithPassword(options.PrivateKey, pvtPW)
	if err != nil {
		panic(fmt.Errorf("Private key could not be loaded, %s", err))
	}

	// load certificate authority private key
	fmt.Printf("\nCertificate Authority private key password: ")
	caPW, err := terminal.ReadPassword(0)
	if err != nil {
		panic(fmt.Errorf("Could not read password: %s", err))
	}
	caKey, err := util.LoadPrivateKeyWithPassword(options.CAPrivateKey, caPW)
	if err != nil {
		panic(fmt.Errorf("CA Private key could not be loaded, %s", err))
	}

	// load settings and authorized keys
	settings, err := util.SettingsLoad(options.Args.YamlFile, options.AuthorizedKeys)
	if err != nil {
		panic(fmt.Errorf("Settings could not be loaded : %s", err))
	}

	// check ip
	if net.IP(options.IPAddress) == nil {
		panic(fmt.Sprintf("Invalid ip address %s", options.IPAddress))
	}

	Serve(options, privateKey, caKey, settings)

}
