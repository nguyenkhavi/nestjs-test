pipeline {
    agent none
    environment {
        project_name="web3asy-proxy"
        DEV_BRANCH="development"
        VAULT_URL="https://vault.spiritlabs.co"
    }
    stages {
        stage("prepare"){
            steps {
                node("master"){
                    checkout scm
                    script {
                        slackSend   channel: "#deploy-notification", 
                                    message: """
@here
Job name: `${env.JOB_NAME}`
Build status: `START BUILD`
Build details: <${env.BUILD_URL}/display/redirect|See in web console>
"""
                    }
                }
            }
        }
        stage("build"){
            steps {
                node("master"){
                        checkout scm
                }
            }
        }

        stage("deploy"){
            parallel {
                stage("dev"){
                    when { branch "$DEV_BRANCH" }
                    steps{
                        node("master"){
                            script {
                                withCredentials([
                                        sshUserPrivateKey(credentialsId:'jenkins-master-ssh-credential' , keyFileVariable: 'identity', passphraseVariable: '', usernameVariable: 'userName'),
                                        string(credentialsId: 'vault-token', variable: 'VAULT_TOKEN')
                                    ]) {
                                    sh 'ssh -o \"StrictHostKeyChecking no\" -i $identity dong@home.spiritlabs.co -p 23 \"cd /home/dong/code/web3asy/web3asy-proxy && zsh scripts/build-dev.sh $DEV_BRANCH $VAULT_TOKEN $VAULT_URL\"'
                                }
                            }

                        }
                    }
                }
            }
        }
    }
    post {
        always {
            node('master'){
                script {
                    def color="danger"
                    if (currentBuild.result=="SUCCESS") {
                        color = "good"
                    }
                    slackSend   channel: "#deploy-notification",
                                color: color,
                                message: """
@here
Job name: `${env.JOB_NAME}`
Build status: `${currentBuild.result}`
Build details: <${env.BUILD_URL}/display/redirect|See in web console>
"""
                }
            }
        }
    }

} 


