# sshagentca

version 0.0.5-beta : 09 June 2020

A server to add ssh user certificates to ssh forwarded agents.

Running the server:

    sshagentca -h
    sshagentca -t <privatekey> -c <caprivatekey> -i <ipaddress> -p <port>
               <settings.yaml>

Example client usage:

    # generate a new key pair, start an ssh agent and add a key
	ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_test	
    ssh-agent > ~/.ssh/agent.env
    source ~/.ssh/agent.env
    ssh-add ~/.ssh/id_test
    <enter password>

    # register ~/.ssh/id_test.pub in the sshagentca settings.yaml file
    # make a new ssh keypair for the server private key
    # make a new ssh keypair for the server certificate authority
    # (the ca key must be password protected)
    # ./sshagentca -t id_pvt -c id_ca -i 10.0.1.99 settings.yaml
    # connect to sshagentca, remembering to forward the agent
    ssh -p 2222 10.0.1.99 -A

    > acmecorp ssh user certificate service
    > 
    > welcome, bob
    > certificate generation complete
    > run 'ssh-add -l' to view
    > goodbye

    # Put id_ca.pub in /etc/ssh/ on the remote server
    # configure the remote server's sshd server with 
    # TrustedUserCAKeys = id_ca.pub (from above)
    # connect to the remote server
    ssh user@remoteserver

The login username that the client provides when connecting to `sshagentca`
is ignored - it does not have to match the `name:` in `settings.yaml`.

Certificates from `sshagentca` can be conveniently used with
[pam-ussh](https://github.com/uber/pam-ussh) to control sudo privileges
on suitably configured servers.

Please refer to the specification at PROTOCOL.certkeys at
https://www.openssh.com/specs.html and the related go documentation at
https://godoc.org/golang.org/x/crypto/ssh.

## Building

```
go get github.com/rorycl/sshagentca
```

The binary will be installed in `~/go/bin/sshagentca` by default.

## Details

The server requires an ssh private key and ssh certificate authority
(CA) private key, with a password required for the CA key at least.
The server will prompt for passwords on startup, or the environmental
variables `SSHAGENTCA_PVT_KEY` and `SSHAGENTCA_CA_KEY` can be set.

Configuration is done in the settings.yaml file and include
certificate settings such as the validity period and organisation name,
the prompt received by the client. Users are configured in the
`user_principals` section, where each user is required to have a name,
ssh public key and list of principals to be set out.

The server will run on the specified IP address and port, by default
0.0.0.0:2222.

If the server runs successfully, it will respond to ssh connections that
have a public key listed in `user_principals` section and which have a
forwarded agent. This response will be to insert an ssh user certificate
into the forwarded agent which is signed by `caprivatekey` with the
parameters set out in `settings.yaml` and restrictions as noted below.

sshagentca generates a new key and corresponding certificate to insert into
the client's ssh-agent.  The key is an ECDSA key pair with a P-384 curve for
fast key generation; the CA key you provide to sign the certificate may be a
different type (e.g. RSA).

Clients can authenticate to sshagentca using any key type supported by go's
`x/crypto/ssh` package.  This includes the ecdsa-sk key used with U2F
security keys, introduced in OpenSSH 8.2.  Hence you can use a physical U2F
token with an OpenSSH 8.2 client to authenticate to sshagentca, whilst the
keys and certificates it issues can be used to login to older versions of
sshd.

## Certificate Restrictions

The project currently has no support for host certificates, although
these could be easily added.

With reference to
https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
there is no support presently for customising *critical options*, and
only the standard *extensions*, such as `permit-agent-forwarding`,
`permit-port-forwarding` and `permit-pty` are permitted.

Each certificate's principals settings are taken from the principals set
out for the specific connecting client public key from the
`user_principals` settings.

The `valid after` timestamp is set according to the `duration` settings
parameter, specified in minutes.  Durations longer than 24 hours are
rejected.

## Key generation

To generate new server keys, refer to man ssh-keygen. For example:

    ssh-keygen -t rsa -b 4096 -f id_server

and specify a password. The id_server file is the private key. Certificate
authority keys are generated in the same way, although adding a comment is often
considered sensible for CA key management, e.g.:

    ssh-keygen -t rsa -b 4096 -f ca -C "CA for example.com"

and choose a password. The ca file is the private key. The ca.pub key in
this example should be used in the sshd_config file on any server for
which you wish to grant certificate-authenticated access. For example:

    TrustedUserCAKeys /etc/ssh/ca.pub

The use of principals to provide "zone" based access to servers is set out at
https://engineering.fb.com/security/scalable-and-secure-access-with-ssh/ 

## Thanks

Thanks to Peter Moody for his pam-ussh announcement at
https://medium.com/uber-security-privacy/introducing-the-uber-ssh-certificate-authority-4f840839c5cc
which was the inspiration for this project, and the comments and help
from him and others on the ssh mailing list.

## License

This project is licensed under the [MIT Licence](LICENCE).

Rory Campbell-Lange 09 June 2020
