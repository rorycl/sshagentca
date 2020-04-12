# sshagentca

version 0.0.3-beta : 12 April 2020

A proof-of-concept project to add ssh user certificates to forwarded ssh
agents using go's ssh packages.

This project is for testing purposes and has not been security audited.

Running the server:

    sshagentca -h
    sshagentca -pvt <privatekey> -ca <caprivatekey> -a <authorized_keys>
                -i <ipaddress> -p <port> settings.yaml

Example client usage:

    source $(ssh-agent)
    ssh-add ~/.ssh/id_test
    <enter password>

    # assuming the public key to id_test is in authorized_keys on the server
    # assuming sshagentca is running on 10.0.1.99; important to forward the agent
    ssh -p 2222 10.0.1.99 -A

    > acmecorp ssh user certificate service
    > 
    > welcome, bob
    > certificate generation complete
    > run 'ssh-add -l' to view
    > goodbye

    # now connect to remote server which has the ca public key and
    # principals files configured, remembering to specify "-A" to forward
    # the agent which now contains the signed certificate
    ssh root@remoteserver -A

Please refer to the specification at PROTOCOL.certkeys at
https://www.openssh.com/specs.html and the related go documentation at
https://godoc.org/golang.org/x/crypto/ssh.

## Details

The server requires an ssh private key and ssh certificate authority
private key, with password protected private keys. The server will
prompt for passwords on startup.

The server requires an `authorized_keys` file with at least one valid
entry. Each entry also requires per-key `user_principals` settings in
the settings yaml file.

The server will run on the specified IP address and port, by default
0.0.0.0:2222.

Settings including certificate settings such as the validity period,
organisation name and the prompt received by the client (together with
the user_principals settings noted above) are set out in the settings
yaml file.

If the server runs successfully, it will respond to ssh connections that
have a public key listed in `authorized_keys` and which have a forwarded
agent. This response will be to insert an ssh user certificate into the
forwarded agent which is signed by `caprivatekey` with the parameters
set out in `settings.yaml` and restrictions as noted below.

The inserted certificate is generated from an ECDSA key pair with a
P-384 curve for fast key generation. 

## Certificate Restrictions

The project currently has no support for host certificates.

With reference to
https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
there is no support presently for customising *critical options*, and
only the standard *extensions*, such as `permit-agent-forwarding`,
`permit-port-forwarding` and `permit-pty` are permitted.

Each certificate's principals settings are taken from the principals set
out in the user_principals settings for the connecting client public
key.

The `valid after` timestamp is set according to the `duration` settings
parameter, specified in minutes.

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

Where an AuthorizedPrincipalsFile must also be configured, such as:

    AuthorizedPrincipalsFile /etc/ssh/ca_principals

The AuthorizedPrincipalsFile contains entries for the users you wish the
certificate to be valid for. To log in, the user is required to be
specified in the AuthorizedPrincipalsFile, the certificate principals
(set in the yaml file) and the user for the connecting ssh client.

## Thanks

Thanks to Peter Moody for his pam-ussh announcement at
https://medium.com/uber-security-privacy/introducing-the-uber-ssh-certificate-authority-4f840839c5cc
which was the inspiration for this project, and the comments and help
from him and others on the ssh mailing list.

## License

This project is licensed under the [MIT Licence](LICENCE).

Rory Campbell-Lange 06 April 2020
