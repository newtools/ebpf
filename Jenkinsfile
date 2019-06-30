pipeline {
  agent {
    docker {
      image "docker.io/njs0/newtools-ebpf-builder"
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
    stage('test') {
      steps {
        sh 'timeout -s KILL 30s bash -e "./ci/run-tests.sh 5.0.13"'
        sh 'timeout -s KILL 30s bash -e "./ci/run-tests.sh 4.19.40"'
      }
    }
  }
  environment {
    CODECOV_TOKEN = credentials('codecov-token')
  }
}