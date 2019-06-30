FROM ubuntu:18.04

ENV GOROOT="/usr/local/go" PATH="/usr/local/go/bin:${PATH}" GOPATH="/root/go" HOME="/root"

# curl and build-essential
RUN apt-get -y update && \
apt-get -y install curl && \
apt-get -y install build-essential

# go stuff
RUN curl -L --fail https://dl.google.com/go/go1.12.6.linux-amd64.tar.gz -o ./go.tar.gz && \
echo "dbcf71a3c1ea53b8d54ef1b48c85a39a6c9a935d01fc8291ff2b92028e59913c go.tar.gz" | sha256sum -c && \
tar -C /usr/local -xzf go.tar.gz && mkdir -p /root/go

# virtme
RUN apt-get -y install python3 && \
apt-get -y install python3-pip && \
pip3 install https://github.com/amluto/virtme/archive/538f1e756139a6b57a4780e7ceb3ac6bcaa4fe6f.zip && \
apt-get -y install qemu-system-x86

# git apparently
RUN apt-get -y install git-core