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
        ls
        pwd
        docker network create mynetwork
        docker run -d -i -t --network=mynetwork --name NPM node:20-alpine
        docker exec -i NPM ls
        docker exec -i NPM pwd        
        echo "${WORKSPACE}"
        docker exec -i NPM mkdir -p ${JOB_BASE_NAME}
        docker cp ${WORKSPACE} NPM:/
        docker exec -i NPM ls
        docker exec -i NPM pwd
        docker exec -i -w /${JOB_BASE_NAME} NPM ls
        docker exec -i -w /${JOB_BASE_NAME} NPM npm install
        docker ps 
        docker network inspect mynetwork        
        '''
      }
    }
    stage('Set up testing environment') {
      steps {
        sh '''
        docker exec -i -w /${JOB_BASE_NAME} NPM npm start & 
        docker run -d -i -t --network=mynetwork --name OWASPZAP -v $(pwd):/zap/wrk/:rw owasp/zap2docker-stable
        docker ps
        '''
      }
    }
    stage('Copy files to OWASP ZAP'){
      steps{
        sh 'docker cp OWASPZAP_scanns/Juice_Shop_baseline.yaml OWASPZAP:/zap/Juice_Shop_baseline.yaml'
      }
    }
    stage('Execute the scan'){
      steps{
           sh '''
           docker exec -i OWASPZAP zap.sh -cmd -autorun /zap/Juice_Shop_baseline.yaml
           docker exec OWASPZAP sh -c ls
           docker exec -i OWASPZAP pwd
           '''
      }
    }
    stage('Export reports'){
      steps{
        sh '''
        pwd
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
