package main

import (
	"fmt"
	flags "github.com/jessevdk/go-flags"
	"github.com/rorycl/sshagentca/util"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"net"
	"os"
)

const VERSION = "0.0.6-beta"
const usage = `<options> <yamlfile>

SSHAgentCA version %s

An SSH server forwarded agent client certificate authority

    sshagentca -h
    sshagentca -t <privatekey> -c <caprivatekey> -i <ipaddress> -p <port>
               <settings.yaml>

The environmental variables SSHAGENTCA_PVT_KEY and SSHAGENTCA_CA_KEY may
be used for the privatekey passwords. The server private key password is
optional.

Application Arguments:

 `

// flag options
type Options struct {
	PrivateKey   string `short:"t" long:"privateKey" required:"true" description:"server ssh private key (optionally password protected)"`
	CAPrivateKey string `short:"c" long:"caPrivateKey" description:"certificate authority private key file (password protected)"`
	IPAddress    string `short:"i" long:"ipAddress" default:"0.0.0.0" description:"ipaddress"`
	Port         string `short:"p" long:"port" default:"2222" description:"port"`
	Args         struct {
		Settings string `description:"settings yaml file"`
	} `positional-args:"yes" required:"yes"`
}

func hardexit(msg string) {
	fmt.Printf("\n\n> %s\n\nAborting startup.\n", msg)
	os.Exit(1)
}

func main() {

	var err error
	var options Options
	var parser = flags.NewParser(&options, flags.Default)
	parser.Usage = fmt.Sprintf(usage, VERSION)

	if _, err = parser.Parse(); err != nil {
		os.Exit(1)
	}

	fmt.Println("SSH Agent CA")

	// load server private key, first trying with no password
	var privateKey ssh.Signer
	privateKey, err = util.LoadPrivateKey(options.PrivateKey)
	if err != nil && err != util.ErrKeyPassphraseRequired {
		hardexit(fmt.Sprintf("Unexpected error: %s", err))

		// retry with password
	} else if err == util.ErrKeyPassphraseRequired {
		var pvtPW = []byte{}
		pvtPWstr := os.Getenv("SSHAGENTCA_PVT_KEY")
		if pvtPWstr != "" {
			pvtPW = []byte(pvtPWstr)
			_ = os.Unsetenv("SSHAGENTCA_PVT_KEY")
		} else {
			fmt.Printf("\nServer private key password: ")
			pvtPW, err = terminal.ReadPassword(0)
			if err != nil {
				hardexit(fmt.Sprintf("Could not read password: %s", err))
			}
		}
		privateKey, err = util.LoadPrivateKeyWithPassword(options.PrivateKey, pvtPW)
		if err != nil {
			hardexit(fmt.Sprintf("Private key could not be loaded, %s", err))
		}
		pvtPW = nil
	}

	// load certificate authority private key
	var caKey ssh.Signer
	var caPW = []byte{}
	caPWstr := os.Getenv("SSHAGENTCA_CA_KEY")
	if caPWstr != "" {
		caPW = []byte(caPWstr)
		_ = os.Unsetenv("SSHAGENTCA_CA_KEY")
	} else {
		fmt.Printf("\nCertificate Authority private key password: ")
		caPW, err = terminal.ReadPassword(0)
		if err != nil {
			hardexit(fmt.Sprintf("Could not read password: %s", err))
		}
	}
	caKey, err = util.LoadPrivateKeyWithPassword(options.CAPrivateKey, caPW)
	if err != nil {
		hardexit(fmt.Sprintf("CA Private key could not be loaded, %s", err))
	}
	caPW = nil

	// load settings yaml file
	settings, err := util.SettingsLoad(options.Args.Settings)
	if err != nil {
		hardexit(fmt.Sprintf("Settings could not be loaded : %s", err))
	}

	// check ip
	if net.IP(options.IPAddress) == nil {
		hardexit(fmt.Sprintf("Invalid ip address %s", options.IPAddress))
	}

	Serve(options, privateKey, caKey, settings)
}
