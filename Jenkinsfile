pipeline {
  agent any
  stages {
    stage('Prune Docker data'){
      steps{
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
    stage('Build') {
      steps {
        sh '''
        docker network create mynetwork
        docker run -d -i -t --network=mynetwork --name NPM node:latest
        docker exec -i NPM ls
        docker exec -i NPM pwd        
        echo ${env.JOB_NAME}
        docker exec -i NPM mkdir -p ${env.JOB_NAME}
        docker cp ${env.JOB_NAME} NPM:${env.JOB_NAME}
        docker exec -i NPM ls
        docker exec -i NPM pwd
        docker exec -i -w ${env.JOB_NAME}/npm_no_docker-compose-app NPM ls
        docker exec -i -w ${env.JOB_NAME}/npm_no_docker-compose-app NPM npm install
        docker ps 
        docker network inspect mynetwork        
          '''
      }
    }
    stage('Set up testing environment') {
      steps {
        sh '''
        docker exec -i -w ${env.JOB_NAME}/npm_no_docker-compose-app NPM npm start & 
        docker run -d -i -t --network=mynetwork --name OWASPZAP -v $(pwd):/zap/wrk/:rw owasp/zap2docker-stable
        docker ps
        '''
      }
    }
    stage('Copy files to OWASP ZAP'){
      steps{
        sh 'docker cp OWASPZAP_scanns/npm-web-app.yaml OWASPZAP:/zap/npm-web-app.yaml'
      }
    }
    stage('Execute the scan'){
      steps{
           sh '''
           docker exec -i OWASPZAP zap.sh -cmd -autorun /zap/npm-web-app.yaml
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
      sh 'docker system prune -a --volumes -f'
    }
  }
}
