package main

import (
	"fmt"
	flags "github.com/jessevdk/go-flags"
	sshlocal "github.com/rorycl/sshagentca/ssh"
	"github.com/rorycl/sshagentca/util"
	"golang.org/x/crypto/ssh/terminal"
	"net"
	"os"
)

const usage = `<options> <yamlfile>

SSH Agent CA

A proof-of-concept SSH server forwarded agent certificate authority

    sshagentca -h
    sshagentca -p <privatekey> -c <caprivatekey> -a <authorized_keys>
               -i <ipaddress> -p <port> settings.yaml

Application Arguments:
 `

func main() {

	var options util.Options
	var parser = flags.NewParser(&options, flags.Default)
	parser.Usage = usage

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

	// load authorized keys
	authorizedKeys, err := util.LoadAuthorizedKeys(options.AuthorizedKeys)
	if err != nil {
		panic(fmt.Errorf("Authorized keys file error : %s", err))
	}

	// load settings
	settings, err := util.SettingsLoad(options.Args.YamlFile, false)
	if err != nil {
		panic(fmt.Errorf("Settings could not be loaded : %s", err))
	}

	// check ip
	if net.IP(options.IPAddress) == nil {
		panic(fmt.Sprintf("Invalid ip address %s", options.IPAddress))
	}

	// fmt.Printf("Options:\n%+v\n", options)
	// fmt.Printf("Privatekey: %s\n", ssh.FingerprintSHA256(privateKey.PublicKey()))
	// fmt.Printf("caKey: %s\n", ssh.FingerprintSHA256(caKey.PublicKey()))
	// fmt.Printf("authorizedKeys len : %d\n", len(authorizedKeys))
	// fmt.Printf("settings: %+v\n", settings)

	sshlocal.Serve(options, privateKey, caKey, authorizedKeys, settings)

}
