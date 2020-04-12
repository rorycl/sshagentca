package util

import (
	"errors"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
)

// load a private key from file
func LoadPrivateKey(filename string) (ssh.Signer, error) {

	fkey, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	sig, err := ssh.ParsePrivateKey(fkey)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// load a private key with password from file
func LoadPrivateKeyWithPassword(filename string, passphrase []byte) (ssh.Signer, error) {

	fkey, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	sig, err := ssh.ParsePrivateKeyWithPassphrase(fkey, passphrase)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// load a raw private key without password from file
func LoadPrivateKeyRaw(filename string) (interface{}, error) {

	fkey, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	sig, err := ssh.ParseRawPrivateKey(fkey)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// load a public key from file
func LoadPublicKey(filename string) (ssh.PublicKey, error) {

	fkey, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(fkey)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// load authorized_keys from file
func LoadAuthorizedKeys(filename string) (map[string]bool, error) {

	// record the found authorized keys
	akeys := map[string]bool{}

	// from https://godoc.org/golang.org/x/crypto/ssh#ex-NewServerConn
	authorizedKeysBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return akeys, err
	}
	if len(authorizedKeysBytes) < 1 {
		return akeys, errors.New("no content in authorized keys file")
	}

	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			return akeys, err
		}
		akeys[string(pubKey.Marshal())] = true
		authorizedKeysBytes = rest
	}
	return akeys, nil
}
