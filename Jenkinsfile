pipeline {
  agent { 
    node { 
      label 'ebpf' 
    } 
  }
  stages {
    stage('test') {
      steps {
        echo '$CODECOV_TOKEN'
      }
    }
  }
  environment {
    CODECOV_TOKEN = credentials('codecov-token')
  }
}
