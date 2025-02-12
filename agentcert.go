package main

import (
	_ "crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"time"

	"github.com/rorycl/sshagentca/util"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Given an agent, CA private key, username and some settings, generate
// an SSH certificate and insert it in the agent.
func addCertToAgent(agentC agent.ExtendedAgent, caKey ssh.Signer, user *util.UserPrincipals, settings util.Settings) error {

	// generate new keys for signing the certificate
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("could not generate ed25519 keys %s", err)
	}

	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("could not convert ed25519 public key to ssh key %s", err)
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
		Key:             sshPubKey,
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
