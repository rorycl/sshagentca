package main

import (
	"fmt"
	"github.com/rorycl/sshagentca/util"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
	"log"
	"net"
	"strings"
	"time"
)

// Serve the SSH Agent Forwarding Certificate Authority Server. The
// server requires connections to have public keys registered in the
// authorized keys file and user_principals fingerprints defined in
// settings.
// Two goroutines, addCertToAgent and handleConnections coordinate to
// add a certificate to the connecting user's ssh connection and to
// print information to their terminal.
// The ssh server is drawn from the example in the ssh server docs at
// https://godoc.org/golang.org/x/crypto/ssh#ServerConn and the Scalingo
// blog posting at
// https://scalingo.com/blog/writing-a-replacement-to-openssh-using-go-22.html
func Serve(options util.Options, privateKey ssh.Signer, caKey ssh.Signer, settings util.Settings) {

	// configure server
	sshConfig := &ssh.ServerConfig{
		// public key callback taken directly from ssh.ServerConn example
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			_, err := settings.UserByFingerprint(ssh.FingerprintSHA256(pubKey))
			if err == nil {
				return &ssh.Permissions{
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(pubKey),
					},
				}, nil
			}
			return nil, fmt.Errorf("unknown public key for %q", c.User())
		},
	}
	sshConfig.AddHostKey(privateKey)

	// setup net listener
	log.Printf("\n\nStarting server connection for %s...", settings.Organisation)
	addr_port := strings.Join([]string{options.IPAddress, options.Port}, ":")
	listener, err := net.Listen("tcp", addr_port)
	if err != nil {
		log.Fatalf("Failed to listen on %s", addr_port)
	} else {
		log.Printf("Listening on %s", addr_port)
	}

	for {
		// make tcp connection
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept incoming connection (%s)", err)
			continue
		}

		// provide handshake
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, sshConfig)
		if err != nil {
			log.Printf("failed to handshake (%s)", err)
			continue
		}

		// extract user
		user, err := settings.UserByFingerprint(sshConn.Permissions.Extensions["pubkey-fp"])
		if err != nil {
			log.Printf("verification error from unknown user %s", sshConn.Permissions.Extensions["pubkey-fp"])
			continue
		}

		// report remote address, user and key
		log.Printf("new ssh connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
		log.Printf("user %s logged in with key %s", user.Name, user.Fingerprint)

		// https://lists.gt.net/openssh/dev/72190
		agentChan, reqs, err := sshConn.OpenChannel("auth-agent@openssh.com", nil)
		if err != nil {
			log.Printf("Could not open agent channel %s", err)
			sshConn.Close()
			continue
		}
		agentConn := agent.NewClient(agentChan)

		// add certificate to agent
		certErr := make(chan error)
		go addCertToAgent(agentConn, caKey, user, settings, certErr)

		// discard incoming out-of-band requests
		go ssh.DiscardRequests(reqs)

		// accept all channels
		go handleChannels(chans, user, settings, sshConn, certErr)
	}
}

// write to the connection terminal, ignoring errors
func termWriter(t *terminal.Terminal, s string) {
	_, _ = t.Write([]byte(s + "\n"))
}

// close the ssh client connection politely
func chanCloser(c ssh.Channel, isError bool) {
	var status = struct {
		Status uint32
	}{uint32(0)}
	if isError == true {
		status.Status = 1
	}
	// https://godoc.org/golang.org/x/crypto/ssh#Channel
	_, err := c.SendRequest("exit-status", false, ssh.Marshal(status))
	if err != nil {
		log.Printf("Could not close ssh client connection: %s", err)
	}
}

// Service the incoming channel. The certErr channel indicates when the
// certificate has finished generation
func handleChannels(chans <-chan ssh.NewChannel, user *util.UserPrincipals,
	settings util.Settings, sshConn *ssh.ServerConn, certErr <-chan error) {

	defer sshConn.Close()

	for thisChan := range chans {
		if thisChan.ChannelType() != "session" {
			thisChan.Reject(ssh.Prohibited, "channel type is not a session")
			return
		}

		// accept channel
		ch, reqs, err := thisChan.Accept()
		defer ch.Close()
		if err != nil {
			log.Println("fail to accept channel request", err)
			return
		}

		// only respond to "exec" type requests
		req := <-reqs
		if req.Type != "auth-agent-req@openssh.com" {
			ch.Write([]byte("request type not supported\n"))
			return
		}

		// terminal
		term := terminal.NewTerminal(ch, "")
		termWriter(term, settings.Banner)
		termWriter(term, fmt.Sprintf("welcome, %s", user.Name))

		// wait for certificate to be done, let user know, then close
		// the connection
	DONE:
		for {
			select {
			case err := <-certErr:
				if err != nil {
					log.Printf("certificate creation error %s\n", err)
					termWriter(term, "certificate creation error")
					termWriter(term, "goodbye\n")
					chanCloser(ch, true)
					break DONE
				} else {
					log.Printf("certificate creation and insertion in agent done\n")
					termWriter(term, "certificate generation complete")
					termWriter(term, "run 'ssh-add -l' to view")
					termWriter(term, "goodbye\n")
					chanCloser(ch, false)
					break DONE
				}
			default:
				time.Sleep(250 * time.Millisecond)
			}
		}
		log.Println("closing the connection")
		sshConn.Close()
		return
	}
}
