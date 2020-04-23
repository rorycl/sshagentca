package main

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
// an SSH certificate and insert it in the agent.
func addCertToAgent(agentC agent.ExtendedAgent, caKey ssh.Signer, user *util.UserPrincipals, settings util.Settings) error {

	// generate a new private key for signing the certificate, and then
	// derive the public key from it
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return fmt.Errorf("Could not generate cert private key %s", err)
	}
	pubKey, err := ssh.NewPublicKey(&privKey.PublicKey)
	if err != nil {
		return fmt.Errorf("Could not generate cert public key %s", err)
	}

	fromT := time.Now().UTC()
	toT := time.Now().UTC().Add(time.Duration(settings.Validity) * time.Minute)
	fmtF := "2006-01-02T15:04"
	fmtT := "2006-01-02T15:04MST"
	timeStamp := fmt.Sprintf("from:%s_to:%s", fromT.Format(fmtF), toT.Format(fmtT))
	identifier := fmt.Sprintf("%s_%s_%s", settings.Organisation, user.Name, timeStamp)
	permissions := ssh.Permissions{}
	permissions.Extensions = settings.Extensions

	cert := &ssh.Certificate{
		CertType:        ssh.UserCert,
		Key:             pubKey,
		KeyId:           identifier,
		ValidAfter:      uint64(fromT.Unix()),
		ValidBefore:     uint64(toT.Unix()),
		ValidPrincipals: user.Principals,
		Permissions:     permissions,
	}
	if err := cert.SignCert(rand.Reader, caKey); err != nil {
		return fmt.Errorf("cert signing error: %s", err)
	}

	err = agentC.Add(agent.AddedKey{
		PrivateKey:   privKey,
		Certificate:  cert,
		LifetimeSecs: settings.Validity * 60, // minutes to seconds
		Comment:      identifier,
	})
	if err != nil {
		return fmt.Errorf("cert signing error: %s", err)
	}

	log.Printf("completed making certificate for %s (fp %s) principals %s expiring %s", user.Name, user.Fingerprint, user.Principals, toT.Format(fmtT))
	return nil
}
