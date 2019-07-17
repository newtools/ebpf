FROM ubuntu:18.04

ENV GOROOT="/usr/local/go" PATH="/usr/local/go/bin:/root/go/bin:${PATH}" GOPATH="/root/go" HOME="/root"

RUN apt -y update && \
    apt-get -y install curl \
        build-essential \
        python3 \
        python3-pip \
        qemu-system-x86 \
        git-core \
        docker.io \
        busybox \
        initramfs-tools-core

# go stuff
RUN curl -L --fail https://dl.google.com/go/go1.12.6.linux-amd64.tar.gz -o ./go.tar.gz && \
    echo "dbcf71a3c1ea53b8d54ef1b48c85a39a6c9a935d01fc8291ff2b92028e59913c go.tar.gz" | sha256sum -c && \
    tar -C /usr/local -xzf go.tar.gz && mkdir -p /root/go && rm ./go.tar.gz

RUN pip3 install https://github.com/amluto/virtme/archive/538f1e756139a6b57a4780e7ceb3ac6bcaa4fe6f.zip

RUN go get golang.org/x/lint/golint && go install golang.org/x/lint/golint
