package ssh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/rorycl/sshagentca/util"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"log"
	"time"
)

// Given an agent, CA private key, username and some settings, generate
// an SSH certificate and insert it in the agent. The done chan sends a
// signal to handleChannels that certificate generation is done
func addCertToAgent(agentC agent.ExtendedAgent, caKey ssh.Signer, username string, settings util.Settings, certErr chan<- error) {

	// generate a new private key for signing the certificate, and then
	// derive the public key from it
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		certErr <- fmt.Errorf("Could not generate cert private key %s", err)
	}
	pubKey, err := ssh.NewPublicKey(&privKey.PublicKey)
	if err != nil {
		certErr <- fmt.Errorf("Could not generate cert public key %s", err)
	}

	fromT := time.Now().UTC()
	toT := time.Now().UTC().Add(time.Duration(settings.Validity) * time.Minute)
	fmtF := "2006-01-02T15:04"
	fmtT := "2006-01-02T15:04MST"
	timeStamp := fmt.Sprintf("from:%s_to:%s", fromT.Format(fmtF), toT.Format(fmtT))
	identifier := fmt.Sprintf("%s_%s_%s", settings.Organisation, username, timeStamp)
	permissions := ssh.Permissions{}
	permissions.Extensions = settings.Extensions

	cert := &ssh.Certificate{
		CertType:        ssh.UserCert,
		Key:             pubKey,
		KeyId:           identifier,
		ValidAfter:      uint64(fromT.Unix()),
		ValidBefore:     uint64(toT.Unix()),
		ValidPrincipals: settings.Principals,
		Permissions:     permissions,
	}
	if err := cert.SignCert(rand.Reader, caKey); err != nil {
		certErr <- fmt.Errorf("cert signing error: %s", err)
	}

	err = agentC.Add(agent.AddedKey{
		PrivateKey:   privKey,
		Certificate:  cert,
		LifetimeSecs: settings.Validity * 60, // minutes to seconds
		Comment:      identifier,
	})
	if err != nil {
		certErr <- fmt.Errorf("cert signing error: %s", err)
	}

	log.Printf("completed making certificate for %s expiring %s", username, toT.Format(fmtT))
	certErr <- nil
}
