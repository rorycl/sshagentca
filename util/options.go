package util

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
