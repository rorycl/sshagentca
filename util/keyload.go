package util

import (
	"errors"
	"os"

	"golang.org/x/crypto/ssh"
)

// ErrKeyPassphraseRequired is a sentinel error for missing passphrases
var ErrKeyPassphraseRequired = errors.New("the ssh key requires a passphrase")

// LoadPrivateKey loads a private key from file (best not to use)
func LoadPrivateKey(filename string) (ssh.Signer, error) {

	fkey, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	sig, err := ssh.ParsePrivateKey(fkey)

	// https://go.googlesource.com/crypto/+/master/ssh/keys_test.go#209
	if err != nil {
		if err == err.(*ssh.PassphraseMissingError) {
			return nil, ErrKeyPassphraseRequired
		}
		return nil, err
	}
	return sig, nil
}

// LoadPrivateKeyWithPassword loads a private key with password from file
func LoadPrivateKeyWithPassword(filename string, passphrase []byte) (ssh.Signer, error) {

	fkey, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	sig, err := ssh.ParsePrivateKeyWithPassphrase(fkey, passphrase)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// LoadPrivateKeyBytesWithPassword loads a private key with password from bytes
func LoadPrivateKeyBytesWithPassword(keyBytes []byte, passphrase []byte) (ssh.Signer, error) {

	sig, err := ssh.ParsePrivateKeyWithPassphrase(keyBytes, passphrase)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// LoadPublicKey loads a public key from file
func LoadPublicKey(filename string) (ssh.PublicKey, error) {

	fkey, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(fkey)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// LoadPublicKeyBytes loads a public key from bytes
func LoadPublicKeyBytes(key []byte) (ssh.PublicKey, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(key)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// LoadAuthorizedKeys loads authorized_keys from file
func LoadAuthorizedKeys(filename string) (map[ssh.PublicKey]bool, error) {

	// record the found authorized keys
	akeys := map[ssh.PublicKey]bool{}

	// from https://godoc.org/golang.org/x/crypto/ssh#ex-NewServerConn
	authorizedKeysBytes, err := os.ReadFile(filename)
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
		akeys[pubKey] = true
		authorizedKeysBytes = rest
	}
	return akeys, nil
}
