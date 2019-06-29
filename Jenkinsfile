pipeline {
  agent {
    node {
      label 'ebpf'
    }

  }
  stages {
    stage('test') {
      steps {
        sh bash -e ./run-tests.sh
      }
    }
  }
  environment {
    CODECOV_TOKEN = credentials('codecov-token')
  }
}