package util

import (
	"errors"
	"fmt"
	yaml "gopkg.in/yaml.v3"
	"io/ioutil"
)

const maxmins uint32 = 24 * 60 // limit max validity to 24 hours

// Restrict the certificate extensions to those commonly supported as
// defined at https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
// Note that the extensions each (only) use an empty string for their
// value
var permittedExtensions = map[string]string{
	// "no-presence-required": "", // only U2F/Fido
	"permit-agent-forwarding": "",
	"permit-port-forwarding":  "",
	"permit-pty":              "",
	"permit-X11-forwarding":   "",
	"permit-user-rc":          "",
}

type Settings struct {
	Validity     uint32            `yaml:"validity"`
	Organisation string            `yaml:"organisation"`
	Banner       string            `yaml:"banner"`
	Extensions   map[string]string `yaml:"extensions,flow"`
	Principals   []string          `yaml:"principals,flow"`
}

// Load a settings yaml file into a Settings struct, optionally setting
// dontValidate to true, which is mainly useful for testing
func SettingsLoad(filepath string, dontValidate bool) (s Settings, err error) {

	filer, err := ioutil.ReadFile(filepath)
	if err != nil {
		return s, err
	}

	err = yaml.Unmarshal(filer, &s)
	if err != nil {
		return s, err
	}

	// return early if no validation required
	if dontValidate == true {
		return s, nil
	}

	err = s.Validate()
	if err != nil {
		return s, err
	}

	return s, nil
}

// Validate the certificate extensions and validity period
func (s *Settings) Validate() error {

	// check validity period
	if !(0 < s.Validity) {
		return errors.New("validity must be >0")
	} else if s.Validity > maxmins {
		return errors.New(fmt.Sprintf("validity must be <%d", maxmins))
	}

	// check extensions meet permittedExtensions
	for k, v := range s.Extensions {
		val, ok := permittedExtensions[k]
		if !ok {
			return errors.New(fmt.Sprintf("extension %s not permitted", k))
		}
		if v != val {
			return errors.New(fmt.Sprintf("value '%s' for key %s not permitted, expected %s", val, k, v))
		}
	}
	return nil
}
