pipeline {
  agent {
    docker {
      image "docker.io/njs0/newtools-ebpf-builder"
      args  '-v /var/run/docker.sock:/var/run/docker.sock --privileged --ipc=host --uts=host --pid=host --security-opt seccomp=unconfined -v /dev:/dev -v /sys:/sys -v /proc:/proc'
    }
  }
  stages {
    stage('build-vet-lint') {
      steps {
        sh 'go get -d ./...'
        sh 'go build ./...'
        sh 'go vet ./...'
        sh 'golint ./...'
      }
    }
    stage('test-5.0') {
      steps {
        sh 'timeout -s KILL 10m ./ci/run-tests.sh 5.0.13'
      }
    }
    stage('test-4.19') {
      steps {
        sh 'timeout -s KILL 10m ./ci/run-tests.sh 4.19.40'
      }
    }
  }
  environment {
    CODECOV_TOKEN = credentials('codecov-token')
  }
}