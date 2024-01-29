pipeline {
  agent any
  stages {
    stage('Prune Docker data'){
      steps{
        script{
          try{ 
            sh 'docker stop $(docker ps -aq)'
          } catch (err){
            echo "Caught: ${err}"
          }
          sh '''       
          docker system prune -a --volumes -f
          '''
          }
        }
      }
    stage('Build') {
      steps {
        sh '''
        docker network create test_network
        docker run -d -i -t --network=test_network --name NPM node:20-alpine   
        docker exec -i NPM mkdir -p ${JOB_BASE_NAME}
        docker cp ${WORKSPACE} NPM:/
        docker exec -i -w /${JOB_BASE_NAME} NPM npm install 
        '''
      }
    }
    stage('Set up testing environment') {
      steps {
        sh '''
        docker exec -i -w /${JOB_BASE_NAME} NPM npm start & 
        docker run -d -i -t --network=test_network --name OWASPZAP -v $(pwd):/zap/wrk/:rw owasp/zap2docker-stable
        '''
      }
    }
    stage('Copy files to OWASP ZAP'){
      steps{
        sh 'docker cp OWASPZAP_scanns/Juice_Shop_ Complete.yaml OWASPZAP:/zap/Juice_Shop_ Complete.yaml'
      }
    }
    stage('Execute the scan'){
      steps{
           sh '''
           docker exec -i OWASPZAP zap.sh -cmd -autorun /zap/Juice_Shop_ Complete.yaml
           '''
      }
    }
    stage('Export reports'){
      steps{
        sh '''
        docker cp OWASPZAP:/zap/ZAP_REPORT.html .
        docker cp OWASPZAP:/zap/ZAP_ALERT_REPORT.md .
        '''
      }
    }
  }
  post {
    always{
      script{
          archiveArtifacts artifacts: 'ZAP_*'
          try{ 
            sh 'docker stop $(docker ps -aq)'
          } catch (err){
            echo "Caught: ${err}"
          }
          sh '''       
          docker system prune -a --volumes -f
          '''
          }
        }
      }
    }
