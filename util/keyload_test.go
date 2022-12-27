package util

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"testing"
)

// will probably only work on linux and derivatives
func init() {
	if runtime.GOOS != "linux" {
		panic("Test only for Linux")
	}
}

var password = []byte("akdjfN57$")

// test ssh rsa private key with no password
func TestLoadRSAKeysNoPassword(t *testing.T) {

	tmpfile, err := ioutil.TempFile("", "rsa")
	if err != nil {
		t.Error(err)
	}
	tname := tmpfile.Name()
	// very crude
	os.Remove(tname)
	pubkey := tname + ".pub"

	f := fmt.Sprintf("-f %s", tname)
	fmt.Println(f)

	out, err := exec.Command(
		"ssh-keygen",
		"-trsa",
		"-b2048",
		fmt.Sprintf("-f%s", tname),
	).Output()
	if err != nil {
		t.Errorf("ssh-keygen failed %s", err)
	} else {
		fmt.Printf("out %s", out)
	}

	_, err = LoadPrivateKey(tname)
	if err != nil {
		t.Errorf("could not read rsa private key without password: %s", err)
	}

	_, err = LoadPublicKey(pubkey)
	if err != nil {
		t.Errorf("could not read rsa public key : %s", err)
	}

	// clean up
	_ = os.Remove(tname)
	_ = os.Remove(pubkey)

}

// test ssh rsa private key with password and public key reading
func TestLoadRSAKeys(t *testing.T) {

	tmpfile, err := ioutil.TempFile("", "rsa")
	if err != nil {
		t.Error(err)
	}
	tname := tmpfile.Name()
	// very crude
	os.Remove(tname)
	pubkey := tname + ".pub"

	f := fmt.Sprintf("-f %s", tname)
	fmt.Println(f)

	out, err := exec.Command(
		"ssh-keygen",
		"-trsa",
		"-b2048",
		fmt.Sprintf("-N%s", password),
		fmt.Sprintf("-f%s", tname),
	).Output()
	if err != nil {
		t.Errorf("ssh-keygen failed %s", err)
	} else {
		fmt.Printf("out %s", out)
	}

	_, err = LoadPrivateKeyWithPassword(tname, password)
	if err != nil {
		t.Errorf("could not read rsa private key with password: %s", err)
	}

	_, err = LoadPublicKey(pubkey)
	if err != nil {
		t.Errorf("could not read rsa public key : %s", err)
	}

	// read the privatekey to check via bytes method
	fkey, err := ioutil.ReadFile(tname)
	if err != nil {
		t.Errorf("could not read rsa private key for parsing: %s", err)
	}
	_, err = LoadPrivateKeyBytesWithPassword(fkey, password)
	if err != nil {
		t.Errorf("could not read rsa private key via bytes: %s", err)
	}

	// try and read the key without a password, which should fail
	_, err = LoadPrivateKey(tname)
	if err != ErrKeyPassphraseRequired {
		t.Errorf("Unexpected error %v", err)
	}

	// clean up
	_ = os.Remove(tname)
	_ = os.Remove(pubkey)

}

// test ssh ecdsa private key with password and public key reading
func TestLoadECDSAKeys(t *testing.T) {

	tmpfile, err := ioutil.TempFile("", "ecdsa")
	if err != nil {
		t.Error(err)
	}
	tname := tmpfile.Name()
	// very crude
	os.Remove(tname)
	pubkey := tname + ".pub"

	f := fmt.Sprintf("-f %s", tname)
	fmt.Println(f)

	out, err := exec.Command(
		"ssh-keygen",
		"-tecdsa",
		"-b384",
		fmt.Sprintf("-N%s", password),
		fmt.Sprintf("-f%s", tname),
	).Output()
	if err != nil {
		t.Errorf("ssh-keygen failed %s", err)
	} else {
		fmt.Printf("out %s", out)
	}

	_, err = LoadPrivateKeyWithPassword(tname, password)
	if err != nil {
		t.Errorf("could not read ecdsa private key with password: %s", err)
	}

	_, err = LoadPublicKey(pubkey)
	if err != nil {
		t.Errorf("could not read ecdsa public key : %s", err)
	}

	// clean up
	_ = os.Remove(tname)
	_ = os.Remove(pubkey)

}

// test ssh ed25519 private key with no password
func TestLoadED25519KeysNoPassword(t *testing.T) {

	tmpfile, err := ioutil.TempFile("", "ed25519")
	if err != nil {
		t.Error(err)
	}
	tname := tmpfile.Name()
	// very crude
	os.Remove(tname)
	pubkey := tname + ".pub"

	f := fmt.Sprintf("-f %s", tname)
	fmt.Println(f)

	out, err := exec.Command(
		"ssh-keygen",
		"-ted25519",
		fmt.Sprintf("-f%s", tname),
	).Output()
	if err != nil {
		t.Errorf("ssh-keygen failed %s", err)
	} else {
		fmt.Printf("out %s", out)
	}

	_, err = LoadPrivateKey(tname)
	if err != nil {
		t.Errorf("could not read ed25519 private key without password: %s", err)
	}

	_, err = LoadPublicKey(pubkey)
	if err != nil {
		t.Errorf("could not read public key : %s", err)
	}

	// clean up
	_ = os.Remove(tname)
	_ = os.Remove(pubkey)

}

// test ssh ed25519 private key with password and public key reading
func TestLoadED25519Keys(t *testing.T) {

	tmpfile, err := ioutil.TempFile("", "ed25519")
	if err != nil {
		t.Error(err)
	}
	tname := tmpfile.Name()
	// very crude
	os.Remove(tname)
	pubkey := tname + ".pub"

	f := fmt.Sprintf("-f %s", tname)
	fmt.Println(f)

	out, err := exec.Command(
		"ssh-keygen",
		"-ted25519",
		fmt.Sprintf("-N%s", password),
		fmt.Sprintf("-f%s", tname),
	).Output()
	if err != nil {
		t.Errorf("ssh-keygen failed %s", err)
	} else {
		fmt.Printf("out %s", out)
	}

	_, err = LoadPrivateKeyWithPassword(tname, password)
	if err != nil {
		t.Errorf("could not read ed25519 private key with password: %s", err)
	}

	_, err = LoadPublicKey(pubkey)
	if err != nil {
		t.Errorf("could not read ed25519 public key : %s", err)
	}

	// read the privatekey to check via bytes method
	fkey, err := ioutil.ReadFile(tname)
	if err != nil {
		t.Errorf("could not read ed25519 private key for parsing: %s", err)
	}
	_, err = LoadPrivateKeyBytesWithPassword(fkey, password)
	if err != nil {
		t.Errorf("could not read ed25519 private key via bytes: %s", err)
	}

	// try and read the key without a password, which should fail
	_, err = LoadPrivateKey(tname)
	if err != ErrKeyPassphraseRequired {
		t.Errorf("Unexpected error %v", err)
	}

	// clean up
	_ = os.Remove(tname)
	_ = os.Remove(pubkey)

}

func writeToFile(content string) (*os.File, error) {

	tmpfile, err := ioutil.TempFile("", "authorized_keys")
	if err != nil {
		return nil, err
	}
	tmpfile.WriteString(content)
	return tmpfile, nil
}

// test empty authorized key file
func TestAuthorizedKeysEmpty(t *testing.T) {
	akeyfile := ``
	af, err := writeToFile(akeyfile)
	if err != nil {
		t.Error(err)
	}
	_, err = LoadAuthorizedKeys(af.Name())
	// should error (empty authorized_keys)
	if err == nil {
		t.Error(af)
	}
	os.Remove(af.Name())
}

// test rsa authorized key in file
func TestAuthorizedKeysOne(t *testing.T) {
	akeyfile := `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2hDa5tDZ0Ji714Gpv+3Eacc1psLCcvQFvP64yaS+AQjhJ50efZwcVyP8Nb3sbcGZC7d+Q3ohGhoiPUkrCtqztDTRR/sjh/XcfDZJhOoodZnkh/3F2+ZB8x192Dm0VfddGQsbQBcLXOVYNeXcq1nne08BHANoJUqIFQ2nS4SextF4GoKPIgOEvajrk3eQf4skzcSRFcFL70Rncus/KsmvzJis7sIOIKnrZAcnBipVjGJrJPaR0jEOGrRfxNioSMzRg4piZc6lfSwOcovmDHMkDrMnKxnw9GvVOezJv0f3Z7ihoRbN43Keway7r5MkaQT4FWYgCRM7kTpN6WPuvURCn test@test.com`
	af, err := writeToFile(akeyfile)
	if err != nil {
		t.Error(err)
	}
	authorizedKeys, err := LoadAuthorizedKeys(af.Name())
	if len(authorizedKeys) != 1 {
		t.Error("number of authorized keys should be one")
	}
	os.Remove(af.Name())
}

// test rsa and ecdsa authorized key in file
func TestAuthorizedKeysTwo(t *testing.T) {
	akeyfile := `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2hDa5tDZ0Ji714Gpv+3Eacc1psLCcvQFvP64yaS+AQjhJ50efZwcVyP8Nb3sbcGZC7d+Q3ohGhoiPUkrCtqztDTRR/sjh/XcfDZJhOoodZnkh/3F2+ZB8x192Dm0VfddGQsbQBcLXOVYNeXcq1nne08BHANoJUqIFQ2nS4SextF4GoKPIgOEvajrk3eQf4skzcSRFcFL70Rncus/KsmvzJis7sIOIKnrZAcnBipVjGJrJPaR0jEOGrRfxNioSMzRg4piZc6lfSwOcovmDHMkDrMnKxnw9GvVOezJv0f3Z7ihoRbN43Keway7r5MkaQT4FWYgCRM7kTpN6WPuvURCn test@test.com
ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBIfis9M22rEKQSRa6QcRn6GPmrea2mp1LKxH4VxTsfOKhGVwjDDro0xlDMD32OA9UDI8WEUuuNJavJXg7u8YIaDZou4L8QvTNNoKiEONiH22KsMO1oV92F7Mifkn7coKGg== test2@test.com`
	af, err := writeToFile(akeyfile)
	if err != nil {
		t.Error(err)
	}
	authorizedKeys, err := LoadAuthorizedKeys(af.Name())
	if len(authorizedKeys) != 2 {
		t.Error("number of authorized keys should be two")
	}
	os.Remove(af.Name())
}
