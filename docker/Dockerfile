# for sshagentca version 0.0.7-beta : September 2021
# https://github.com/rorycl/sshagentca
# RoryCL 21 May 2022

FROM golang:1.22-alpine

# add ssh-keygen
RUN apk add --no-cache --update openssh-keygen && \
    apk add --no-cache --update openssh-server && \
    apk add --no-cache --update git

# WORKDIR /sshagentca
WORKDIR /build

# retrieve latest sshagentca release
# git checkout -b v0.1.0
RUN git clone https://github.com/rorycl/sshagentca.git ./ && \
    git checkout -b main

# setup the go environment; note gcc isn't in alpine
ENV CGO_ENABLED=0
RUN go mod download && \
    go get -d -v ./... && \
    go test ./... && \
    go build

# make leaner target
FROM alpine:latest

# add ssh-keygen
RUN apk add --no-cache --update openssh-keygen && \
    apk add --no-cache --update openssh-server

WORKDIR /app

# https://docs.docker.com/develop/develop-images/multistage-build/
COPY --from=0 /build/sshagentca /app/sshagentca

# environment for the sshagentca server
ENV SSHAGENTCA_PVT_KEY eer4Cei8
ENV SSHAGENTCA_CA_KEY aifeF0Oo
ENV SSHAGENTCA_PORT 2222

# settings
# remember add a user with an ssh key to the settings file in order to
# test the server
COPY settings.yaml ./

# generate keys for the server
RUN ssh-keygen -t ed25519 -f id_pvt -N ${SSHAGENTCA_PVT_KEY} > /dev/null 2>&1 && \
    ssh-keygen -t ed25519 -f id_ca -N ${SSHAGENTCA_CA_KEY} > /dev/null 2>&1

# setup the ssh server keys, trusteduserca keys configuration
RUN ssh-keygen -A && \
    echo "TrustedUserCAKeys /app/id_ca.pub" >> /etc/ssh/sshd_config && \
    echo "LogLevel VERBOSE" >> /etc/ssh/sshd_config && \
    echo "Port 48084" >> /etc/ssh/sshd_config

# enable root user for login
RUN sed -i s/root:!/"root:*"/g /etc/shadow

EXPOSE 2222 48084

# run the sshagentca server and ssh server
# CMD ./sshagentca -t id_pvt -c id_ca -p ${SSHAGENTCA_PORT} settings.yaml
# ENTRYPOINT service ssh restart
# CMD ["/usr/sbin/sshd", "-D"]

# run sshd and sshagentca
COPY run.sh run.sh
CMD /app/run.sh
