pipeline {
  agent {
    node {
      label 'ebpf'
    }

  }
  stages {
    stage('prep') {
      steps {
        sh 'curl -L --fail https://dl.google.com/go/go1.12.6.linux-amd64.tar.gz -o ./go.tar.gz'
        sh 'echo "dbcf71a3c1ea53b8d54ef1b48c85a39a6c9a935d01fc8291ff2b92028e59913c go.tar.gz" | sha256sum -c'
        sh 'tar -C /usr/local -xzf go.tar.gz'
        sh 'export PATH=$PATH:/usr/local/go'
      }
    }
    stage('build-vet-lint') {
      steps {
        sh 'go get -d ./...'
        sh 'go get build ./...'
        sh 'go vet ./...'
        sh 'go install golang.org/x/lint/golint'
        sh '$GOPATH/bin/golint ./...'
      }
    }
    stage('test') {
      steps {
        sh 'sudo pip3 install https://github.com/amluto/virtme/archive/538f1e756139a6b57a4780e7ceb3ac6bcaa4fe6f.zip'
        sh 'apt-get -y update'
        sh 'apt-get install -y qemu-system-x86'
        sh 'timeout -s KILL 30s bash -e ".ci/run-tests.sh 5.0.13"'
        sh 'timeout -s KILL 30s bash -e ".ci/run-tests.sh 4.19.40"'
      }
    }
  }
  environment {
    CODECOV_TOKEN = credentials('codecov-token')
  }
}