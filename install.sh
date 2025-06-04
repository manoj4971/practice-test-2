#!/bin/bash
shopt -s extglob

source versions.properties
DEFAULT_DOCKER_REGISTRY_HOST="161945688208.dkr.ecr.us-east-1.amazonaws.com"
DEFAULT_DOCKER_REGISTRY_PORT="443"

function check-return {
  local return_code=$1
  if [ ${return_code} -ne 0 ];then
    exit ${return_code}
  fi
}

function password_check {
  # map .atr.properties key to consul key
  declare -A keys_mapping

  keys_mapping[ADMIN_PASSWORD]=configuration/aaam-atr-v3-identity-management/admin.password
  keys_mapping[RABBIT_PASSWORD]=configuration/aaam-atr-v3-automation-queue/spring.rabbitmq.password
  keys_mapping[MONGO_PASSWORD]=configuration/aaam-atr-v3-ticket-management/spring.data.mongodb.password
  keys_mapping[WORKER_PASSWORD]=configuration/aaam-atr-v3-identity-management/default-worker.password
  keys_mapping[BOT_PASSWORD]=configuration/aaam-bot/bot.core.basic.admin.password
  keys_mapping[AUTH_PASSWORD]=configuration/aaam-atr-v3-identity-management/auth.password
  #keys_mapping[ES_PASSWORD_ATR]=configuration/aaam-atr-v3-ticket-management/elasticSearch.password

  for key in "${!keys_mapping[@]}";
  do
    echo checking "$key";
    current_password=`docker exec consul consul kv get ${keys_mapping[$key]}`

    # check consul value against .atr.properties value
    # added one additional condition to check if the key is empty
    # if the key is empty, the process will not be terminated because previously BOT_PASSWORD does not
    # exist in .atr.properties
    # so the process will only be terminated when the key is NOT empty & the values don't match
    if [ $current_password != "${!key}" ] && [ ! -z "$key" ];
    then
      echo "$key does not match with the one in the existing system, exiting upgrade process ..."
      exit 1
    fi
  done

  #Check Postgres password
  #Postgres password is not in Consul, so it needs to be retrieved by doing a reverse container of atr-postgres
  reverse_container_postgres=`${INSTALLATION_FOLDER}/utils/reverse_container.sh atr-postgres`
  current_password=$(echo "$reverse_container_postgres" | awk -F'POSTGRES_PASSWORD=' ' { print $NF } ')
  current_password=$(echo $current_password | cut -d "'" -f1)
  postgres_line=`cat ${ENV_FILE} | grep POSTGRES_PASSWORD`

  if [ ! -z "$postgres_line" ]; then
    properties_file_password=$(echo $postgres_line | cut -d'"' -f 2)

    if [ $current_password != $properties_file_password ]; then
      echo "POSTGRES_PASSWORD does not match with the one in the existing system or is missing, exiting upgrade process ..."
      exit 1
    fi
  else
    echo "POSTGRES_PASSWORD was not found on .atr.properties, exiting upgrade process ..."
    exit 1
  fi

}



# Check
function ansible_with_bash_fallback {
  local playbook=$1
  local bash_file=$2
  local extra_docker_option=$3
  docker run --rm --name ansible \
    --privileged \
    ${extra_docker_option} \
    -e ANSIBLE_CONFIG=/ansible-scripts/ansible.cfg \
    ${MOUNT_DOCKER_SOCK} \
    --volume ${INSTALLATION_FOLDER}:${INSTALLATION_FOLDER}:z \
    --volume ${DIR}/ansible-scripts:/ansible-scripts:z \
    --volume ${DIR}/dependencies:/dependencies:z \
    --volume ${UTILS_DIR}:/utils:z \
    ${ANSIBLE_IMAGE} -e@/utils/.ansible-env.yml -i /ansible-scripts/inventory --connection=local --limit localhost /ansible-scripts/${playbook}
  if [ "$DOCKER_SOCK_MOUNT_ALLOWED" == "false" ]; then
    docker run --rm --name ansible\
    --volume ${DIR}:/install-scripts \
    --entrypoint=python \
    --user=$(id -u ${INSTALLATION_USER}) \
    ${ANSIBLE_IMAGE} /install-scripts/ansible-to-docker.py ${UTILS_DIR}/.ansible-env.yml -b / -g /install-scripts/ansible-scripts/group_vars/local.yml -p /install-scripts/ansible-scripts/${playbook} -o /install-scripts/${bash_file}
    bash ${DIR}/${bash_file}
  fi
}

function deleteOldRabbitmqExchanges() {
  # step to delete old exchanges
      get_consul=`docker ps -a | grep consul`
      if [[ "${get_consul}" ]]; then
         rbmq_password=$(docker exec consul consul kv get configuration/aaam-atr-v3-ticket-management/spring.rabbitmq.password)
         get_rabbitmq_container=`docker ps -a | grep rabbitmq`
         if [[ "${get_rabbitmq_container}" ]]; then
            docker exec rabbitmq bash -c "rabbitmqadmin -u atr -p ${rbmq_password}  delete exchange  --vhost automation-queue name=bulk_action_exchange"
            docker exec rabbitmq bash -c "rabbitmqadmin -u atr -p ${rbmq_password}  delete exchange  --vhost automation-queue name=ticket_poll_delayed_exchange"
            docker exec rabbitmq bash -c "rabbitmqadmin -u atr -p ${rbmq_password}  delete exchange  --vhost automation-queue name=async_task_reply"
         else
            echo "No Container - rabbitmq"
         fi
      else
         echo "No Container - consul"
      fi
      # end of steps to delete old exchanges
}

function help {
  echo "Use this script to perform the atr installation."
  echo
  echo "Installation logs will be written to installation.log file, you can commmunicate this file to support if you encounter any issues."
  echo
  echo "SYNOPSIS"
  echo "  install.sh <OPTION>"
  echo
  echo "DESCRIPTION"
  echo "  The following OPTION arguments are available:"
  echo "   -h: Displays this help"
  echo "   -c: Configuration file"
}

# Parse command line and construct a list of variable definition that will be evaluated later
while getopts "hc:" arg; do
  case $arg in
    h)
      help
      exit 0
    ;;
    c)
      INPUT_ENV_FILE="${OPTARG}"
    ;;
    \?)
      echo "Unknown option: -$OPTARG" >&2
      echo
      help
      exit -1
      ;;
    :)
      echo "Missing option argument for -$OPTARG" >&2
      help
      exit -1
    ;;
    esac
done


# Getting the name of the current directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
UTILS_DIR=${DIR}/script-utils


ENV_FILE="${UTILS_DIR}/.atr.properties"
if [ ! -z ${INPUT_ENV_FILE} ]; then
  echo "We are going to use the configuration specified in ${INPUT_ENV_FILE}"
  cp "${INPUT_ENV_FILE}" "${ENV_FILE}"
else
  # Set XTERM to have proper colors
  export TERM=xterm
  python ${UTILS_DIR}/inquire.py
  check-return $?
fi
source ${ENV_FILE}

# Creates installation log
exec >  >(tee -ia installation.log)
exec 2> >(tee -ia installation.log >&2)


# First, perform some checks to make sure that the prerequisites are ok
${UTILS_DIR}/precheck.sh ${ENV_FILE}
check-return $?

# Set docker repo for pulling images if specified in configuration file, otherwise use default.
DOCKER_REGISTRY_HOST=$(cat ${ENV_FILE}| grep "docker_registry\.host"| awk 'BEGIN { FS="="} /^[^#]/ {print $2}'| tr -d "\"|'")
DOCKER_REGISTRY_PORT=$(cat ${ENV_FILE}| grep "docker_registry\.port"| awk 'BEGIN { FS="="} /^[^#]/ {print $2}'| tr -d "\"|'")
DOCKER_REGISTRY_HOST=${ECR_URL:-$DEFAULT_DOCKER_REGISTRY_HOST}
DOCKER_REGISTRY_PORT=${DOCKER_REGISTRY_PORT:-$DEFAULT_DOCKER_REGISTRY_PORT}
ANSIBLE_IMAGE=${ECR_URL}/atr-v3-ansible:${ATR_INFRA_ANSIBLE_VERSION}

sed -i 's/ECR_URL/${ECR_URL}/' ${DIR}/ansible-scripts/atr/scripts/generateMongoSSLCert.sh
sed -i 's/ECR_URL/${ECR_URL}/' ${DIR}/ansible-scripts/atr/scripts/elasticsearch/replication.sh

echo
echo "-----------------------------"
echo "Import Docker images"
echo "-----------------------------"
shopt -s nullglob
# Import images provided inside the archive file
export ECR_URL=${ECR_URL}
for f in ${DIR}/images/*.tar.gz; do
  ${UTILS_DIR}/dockerimages.sh import $f
done
shopt -u nullglob


# Import additional images listed in images.list
if [ -f images.list ]; then
  AWSCLI=$(which aws 2>/dev/null)
  if [ -z ${AWSCLI} ]; then
    echo "AWS CLI not found, extracting to installation folder"
    unzip ${DIR}/dependencies/aws/awscli-bundle.zip -d ${INSTALLATION_FOLDER}
    echo "Installing AWS CLI and creates symlink at /bin/aws"
    ${INSTALLATION_FOLDER}/awscli-bundle/install -b /bin/aws
  else
    echo "AWS CLI is already installed"
  fi
  echo "Logging into ECR Prod repositories"
  docker login --username AWS --password-stdin 161945688208.dkr.ecr.ap-southeast-2.amazonaws.com <<< $(aws ecr get-login-password --region ap-southeast-2)
  # Check if the user has a non_prod aws key set up for UAT purpose
#  if grep -Fq "non_prod_aws" ~/.aws/credentials
#  then
#    echo "Detected non-prod profile, attempting to authenticate"
#        docker login --username AWS --password-stdin 546363320159.dkr.ecr.ap-southeast-2.amazonaws.com <<< $(aws ecr get-login-password --region ap-southeast-2)
#  fi

  for image in $(cat images.list); do
    # Update image repo
    # image=$(echo $image| sed 's/'${DEFAULT_DOCKER_REGISTRY_HOST}':'${DEFAULT_DOCKER_REGISTRY_PORT}'/'${DOCKER_REGISTRY_HOST}':'${DOCKER_REGISTRY_PORT}'/g')
    image=$(echo $image| sed 's/'${DEFAULT_DOCKER_REGISTRY_HOST}'/'${ECR_URL}'/g')
    image_id=$(docker images -q -f reference=${image})
    if [ -z "${image_id}" ];then
        echo "Pulling $image"
        docker pull $image
    else
        echo "$image already downloaded -> no pull"
    fi
  done
fi


# Test if we can issue docker commands through /run/docker.sock
MOUNT_TEST=$(docker run --privileged --rm --entrypoint=python -v /var/run/docker.sock:/var/run/docker.sock:z ${ANSIBLE_IMAGE} -c 'import docker;docker.from_env().containers.list()'  &> /dev/null)
DOCKER_SOCK_MOUNT_ALLOWED=$?
if [ "$DOCKER_SOCK_MOUNT_ALLOWED" == "1" ]; then
  DOCKER_SOCK_MOUNT_ALLOWED='false'
else
  DOCKER_SOCK_MOUNT_ALLOWED='true'
fi

ANSIBLE_ENV_FILE=${UTILS_DIR}/.ansible-env.yml

if [ -f ${ANSIBLE_ENV_FILE} ]; then
  rm ${ANSIBLE_ENV_FILE}
fi

# Add image repo to environmental file
echo "docker_registry:" >> ${ANSIBLE_ENV_FILE}
echo "  host: ${DOCKER_REGISTRY_HOST}" >> ${ANSIBLE_ENV_FILE}
echo "  port: ${DOCKER_REGISTRY_PORT}" >> ${ANSIBLE_ENV_FILE}

# Fetch env variables set by the generate_env script and add DOCKER_SOCK_MOUNT_ALLOWED to these vars
# the env file is a properties file, thus we convert it to yaml
sed 's/=/: /1' ${ENV_FILE} >> ${ANSIBLE_ENV_FILE}
sed 's/=/: /1' ${DIR}/versions.properties >> ${ANSIBLE_ENV_FILE}
echo "DOCKER_SOCK_MOUNT_ALLOWED: ${DOCKER_SOCK_MOUNT_ALLOWED}" >> ${ANSIBLE_ENV_FILE}
echo "INSTALLATION_USER: $(id -u ${INSTALLATION_USER_NAME})" >> ${ANSIBLE_ENV_FILE}
echo "INSTALLATION_GROUP: $(getent group ${INSTALLATION_GROUP_NAME} | cut -d ':' -f3)" >> ${ANSIBLE_ENV_FILE}
PACKAGE_VERSION=$(cat ${DIR}/build.properties | grep FULL_VERSION | cut -d= -f2)
echo "PACKAGE_VERSION: ${PACKAGE_VERSION}" >> ${ANSIBLE_ENV_FILE}

# Marketplace
# Check if ACN deployment
ACN_ACCOUNT_IDS=("161945688208" "546363320159")
INSTANCE_IDENTITY=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document)
ACCOUNT_ID=$(echo "$INSTANCE_IDENTITY" | grep '"accountId"' | sed -E 's/.*"accountId"\s*:\s*"([0-9]+)".*/\1/')
IS_ACN_CLOUD=$(printf '%s\n' "${ACN_ACCOUNT_IDS[@]}" | grep -q -w "$ACCOUNT_ID" && echo "true" || echo "false")
echo "IS_ACN_CLOUD: ${IS_ACN_CLOUD}" >> ${ANSIBLE_ENV_FILE}
# Check if EU deployment
AVAILABILITY_ZONE=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)
REGION=${AVAILABILITY_ZONE::-1}
IS_EU_REGION=$( [[ $REGION == eu-* ]] && echo "true" || echo "false" )
echo "IS_EU_REGION: ${IS_EU_REGION}" >> ${ANSIBLE_ENV_FILE}

# Check if build.properties file exists within install directory to determine if upgrading an existing ATR installation
# Check if first install
echo
echo "-------------------------------------------------------------------"
echo "Determining install/Upgrade behaviour"
echo "-------------------------------------------------------------------"

if [[ ! -e "${INSTALLATION_FOLDER}" ]]; then
    # First install, no need to perform any upgrade tasks, set to new version
    echo "no install Dir, no upgrade"
    echo "EXISTING_PACKAGE_VERSION: ${PACKAGE_VERSION}" >> ${ANSIBLE_ENV_FILE}
# Check if existing install
elif [[ -e "${INSTALLATION_FOLDER}/build.properties" ]]; then
    # Determine existing install version from build.properties file
    echo "existing install with build.properties"
    EXISTING_PACKAGE_VERSION=$(cat ${INSTALLATION_FOLDER}/build.properties | grep FULL_VERSION | cut -d= -f2)
    echo "EXISTING_PACKAGE_VERSION: ${EXISTING_PACKAGE_VERSION}" >> ${ANSIBLE_ENV_FILE}

    #enable pre-requisites for rabbitmq upgrade
    get_rabbitmq_container=`docker ps -a | grep rabbitmq`
    if [[ "${get_rabbitmq_container}" ]]; then
        docker exec rabbitmq sh -c 'rabbitmqctl enable_feature_flag all'
    else
      echo "No Container - rabbitmq"
      read -p "Do you want to stop the installation to avoid issues? (yes|no): " yn
      if [[ "${yn}" == 'y' || "${yn}" == 'yes' ]]; then
         echo "The installation was stopped"
         exit 1
      fi
    fi
    #end of pre-requisites for rabbitmq upgrade

is_consul=`docker ps -a | grep consul`

# The below block only applicable for version < 4.0.0
if [ "$(echo "${PACKAGE_VERSION}" | grep -c '^3.*')" == '1' ] ; then
  #Validate the ES PASSWORD mistmatch. While ATR upgrades

  if [[ "${is_consul}" ]]; then
        echo "Validating ES PASSWORD Before upgrading"
        # check if pass password validation check
        current_password=$(docker exec consul consul kv get configuration/aaam-atr-v3-ticket-management/elasticSearch.password)

        # CAMS instance specific validation

        properties_file_password=`cat ${ENV_FILE} | grep ES_PASSWORD_ATR | cut -d '"' -f 2`
        if [[ ${#properties_file_password} -gt 16 ]]; then
            properties_file_password=`cat ${ENV_FILE} | grep ES_PASSWORD_ATR | cut -d '=' -f 2`
            properties_file_password="${properties_file_password#"${properties_file_password%%[![:space:]]*}"}"
            trim_password=\"${properties_file_password}\"
            sed -i "s/$properties_file_password/$trim_password/g"  ${ENV_FILE}
        fi

        # CAMS specific validation ENDS ...

        if [ $current_password != $properties_file_password ]; then
          sed -i "s/$properties_file_password/$current_password/g" ${ENV_FILE}
          echo "*****************************************"
          echo "ES_PASSWORD_ATR is presereved Now ......."
          echo "*****************************************"
        fi

    else
      # container not found.
      echo "Container not found . Assuming new Installation and proceeding ............"
  fi

  #End ES Password mismatch check
fi
# End of blcok for versions < 4.0.0





    # step to delete old exchanges
    if [[ "${is_consul}" ]]; then
       rbmq_password=$(docker exec consul consul kv get configuration/aaam-atr-v3-ticket-management/spring.rabbitmq.password)
       if [[ "${get_rabbitmq_container}" ]]; then
          docker exec rabbitmq bash -c "rabbitmqadmin -u atr -p ${rbmq_password}  delete exchange  --vhost automation-queue name=bulk_action_exchange"
          docker exec rabbitmq bash -c "rabbitmqadmin -u atr -p ${rbmq_password}  delete exchange  --vhost automation-queue name=ticket_poll_delayed_exchange"
          docker exec rabbitmq bash -c "rabbitmqadmin -u atr -p ${rbmq_password}  delete exchange  --vhost automation-queue name=async_task_reply"
       else
          echo "No Container - rabbitmq"
       fi
    else
       echo "No Container - consul"
    fi
    # end of steps to delete old exchanges

# this fix applicable only for versions < 4.3.0

if [[ -e "${INSTALLATION_FOLDER}" ]]; then
  atr_current_version=${EXISTING_PACKAGE_VERSION:0:5}
  new_atr_version=4.3.0
  echo "EXISTING_PACKAGE_VERSION: ${current_atr_version}"
  if [[ ((${atr_current_version} < ${new_atr_version})) ]]
  then
    complex_password=$(python ${UTILS_DIR}/generate_complex_password.py)
    echo "complex_password: "+$complex_password
    EXISTING_ENV=${INSTALLATION_FOLDER}/.atr.properties
    existing_es_password=`cat ${EXISTING_ENV} | grep ES_PASSWORD_ATR | cut -d '"' -f 2`
    sed -i "s/$existing_es_password/$complex_password/g"  ${EXISTING_ENV}
    sed -i "s/$existing_es_password/$complex_password/g" ${ENV_FILE}
  fi
fi


# End of ES password complexity fix

    get_consul_container=`docker ps -a | grep consul`

    # container found.
    if [[ "${get_consul_container}" ]]; then
      # check if pass password validation check
      password_check
    else
      # container not found.
      echo "We have detected the ATR has previously been installed on this instance however can not confirm that the system passwords are correct."
      read -p "Do you want to stop the installation to avoid overwriting? (yes|no): " yn
      if [[ "${yn}" == 'y' || "${yn}" == 'yes' ]]; then
         echo "The installation was stopped"
         exit 1
      fi
    fi

    #elasticSearch legacy index removal fix
    es_container=`docker ps -a | grep elasticsearch`

    if [[ "${get_consul_container}" ]];  then
      echo "Pull ES Values from config"
      ELASTICSEARCH_USERNAME=`docker exec consul consul kv get configuration/aaam-atr-v3-ticket-management/elasticSearch.username`
      ELASTICSEARCH_PWD=`docker exec consul consul kv get configuration/aaam-atr-v3-ticket-management/elasticSearch.password`
      if [[ "${es_container}" ]] ; then
         echo "Deleting Legacy templates of elasticsearch"
         docker exec elasticsearch sh -c "curl -X DELETE http://localhost:9200/_index_template/ss4o_metric_* -u ${ELASTICSEARCH_USERNAME}:${ELASTICSEARCH_PWD}"
         docker exec elasticsearch sh -c "curl -X DELETE http://localhost:9200/_index_template/ss4o_trace_* -u ${ELASTICSEARCH_USERNAME}:${ELASTICSEARCH_PWD}"
       else
         echo "No Container"
      fi
     else
        echo "No Container - consul"
    fi


    #end of elasticSearch legacy index fix

    #clean bot messages and conversations index when upgrading from 3.x.x to 4.x.x
    if [ "$(echo "${PACKAGE_VERSION}" | grep -c '^3.*')" == '1' ] ; then
      echo "Upgrade from 3.x.x to 4.x.x => clean bot messages and conversations indices"
      es_container=$(docker ps -a | grep elasticsearch)

      if [[ "${get_consul_container}" ]];  then
        ELASTICSEARCH_USERNAME=$(docker exec consul consul kv get configuration/aaam-atr-v3-ticket-management/elasticSearch.username)
        ELASTICSEARCH_PWD=$(docker exec consul consul kv get configuration/aaam-atr-v3-ticket-management/elasticSearch.password)
        if [[ "${es_container}" ]] ; then
          docker exec elasticsearch sh -c "curl -X DELETE http://localhost:9200/*-chatbot-conversations-* -u ${ELASTICSEARCH_USERNAME}:${ELASTICSEARCH_PWD}"
          docker exec elasticsearch sh -c "curl -X DELETE http://localhost:9200/*-chatbot-messages-* -u ${ELASTICSEARCH_USERNAME}:${ELASTICSEARCH_PWD}"
          docker exec elasticsearch sh -c "curl -X DELETE http://localhost:9200/*-chatbot-sessions-* -u ${ELASTICSEARCH_USERNAME}:${ELASTICSEARCH_PWD}"
          docker exec elasticsearch sh -c "curl -X DELETE http://localhost:9200/*-nlp-* -u ${ELASTICSEARCH_USERNAME}:${ELASTICSEARCH_PWD}"

        else
          echo "ES container is missing: failed to delete bot conversations and messages indices"
        fi
      else
          echo "Consul container is missing: failed to delete bot conversations and messages indices"
      fi
    fi
    #clean bot messages and conversations index

# Handle case where this seamless upgrade framework was introduced
else
    # Set hardcoded release version (SORRY)
    # Check to see if client container exists
    docker inspect client >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        # client container exists, pull package version from there
        echo "Pulling release version from client container env variable"
        echo "EXISTING_PACKAGE_VERSION: $(docker inspect client --format {{.Config.Env}} | grep -o -e "PACKAGE_VERSION=[^[:space:]]*" | cut -d= -f2)" >> ${ANSIBLE_ENV_FILE}
        password_check
    else
        # Fall back assumes current version
        echo "Unable to determine current version. Behaving as clean install"
        echo "EXISTING_PACKAGE_VERSION: ${PACKAGE_VERSION}" >> ${ANSIBLE_ENV_FILE}
    fi
fi





# Generate the Ansible command that will be used to execute the playbooks
# NB : Ansible will run inside a docker container (aaam-ansible).
#      In some secure contexts (SE Linux) we are not allowed to mount the docker socket of the host inside the container.
#      Without this, ansible won't be able do run docker containers.
#      In this case, we run the playbook without mounting the sockets (it runs all tasks that do not need docker)
#      and then the docker-related tasks are converted into a bash script executed directly on the host.
if [ "$DOCKER_SOCK_MOUNT_ALLOWED" == "true" ]; then
  MOUNT_DOCKER_SOCK="--volume /var/run/docker.sock:/var/run/docker.sock:z"
else
  MOUNT_DOCKER_SOCK=""
  echo
  echo "-------------------------------------------------------------------"
  echo "Warning : the docker socket cannot be mounted inside the containers"
  echo "Some advanced features will not be available"
  echo "-------------------------------------------------------------------"
fi

function addConsulKeys() {
  consul_container=`docker ps -a | grep consul`

  #TODO: Plan to remove in next upcoming releases -> 4.2.0 or 4.3.0
  if [[ -e "${INSTALLATION_FOLDER}" ]]; then
     if [[ "${consul_container}" ]]; then
      bash ${DIR}/ansible-scripts/consul/automation-worknotes.sh
    else
      echo "Consul container not found......"
    fi
  fi
  #END

  #set default landing page key , value
  # container found.
  if [[ "${consul_container}" ]]; then
    # add consul key valur for default landing page
    out=`docker exec consul consul kv put configuration/aaam-atr-v3-identity-management/landingPage.url /`
    echo "added default landingpage key value to Consul"
  else
    echo "container not found......"
  fi
}

out=$(docker network create atr_net 2>/dev/null)

echo
echo "-----------"
echo "Setup volumes"
echo "-----------"
ansible_with_bash_fallback "docker-volumes/playbook.yml" "ansible-docker-volumes.sh"

echo
echo "-----------"
echo "Setup vault"
echo "-----------"
ansible_with_bash_fallback "vault/playbook.yml" "ansible-vault.sh" '--network=atr_net'

echo
echo "-----------"
echo "Setup consul"
echo "-----------"
ansible_with_bash_fallback "consul/playbook.yml" "ansible-consul.sh" '--network=atr_net'

if [[ ((${atr_current_version} < ${new_atr_version})) ]]; then

  if [[ "${is_consul}" ]]; then
      echo "==== update complex es password to consul ===="
      tm_es=`docker exec consul consul kv put configuration/aaam-atr-v3-ticket-management/elasticSearch.password $complex_password`
      bot_es=`docker exec consul consul kv put configuration/aaam-bot/bot.core.elasticsearch.password $complex_password`
      bot_metric_es=`docker exec consul consul kv put configuration/aaam-bot/management.metrics.export.elastic.password $complex_password`
      slack_es=`docker exec consul consul kv put configuration/slack-relay/management.metrics.export.elastic.password $complex_password`
      teams_es=`docker exec consul consul kv put configuration/teams-relay/management.metrics.export.elastic.password $complex_password`
      echo "==== end of complex es passowrd update to consul ===="
  fi

fi

addConsulKeys

echo
echo "-----------"
echo "Setup mongodb"
echo "-----------"
ansible_with_bash_fallback "mongo/playbook.yml" "ansible-mongo.sh" '--network=atr_net'

echo
echo "-----------"
echo "Setup mongodb for ML"
echo "-----------"
ansible_with_bash_fallback "mongo/playbook-ml.yml" "ansible-mongo-ml.sh" '--network=atr_net'


echo
echo "-----------"
echo "Setup elasticsearch"
echo "-----------"
ansible_with_bash_fallback "elasticsearch/playbook.yml" "ansible-elasticsearch.sh" '--network=atr_net'

echo
echo "-----------"
echo "Setup rabbitmq"
echo "-----------"
ansible_with_bash_fallback "rabbitmq/playbook.yml" "ansible-rabbitmq.sh" '--network=atr_net'

echo
echo "-----------"
echo "Setup nginx"
echo "-----------"
ansible_with_bash_fallback "nginx/playbook.yml" "ansible-nginx.sh" '--network=atr_net'

echo
echo "-----------"
echo "Setup rundeck"
echo "-----------"
ansible_with_bash_fallback "rundeck/playbook.yml" "ansible-rundeck.sh" '--network=atr_net'

#Update rundeck tables after rundeck upgrade when existing version is less than 4.1.0
if [[ -e "${INSTALLATION_FOLDER}" ]]; then
  current_atr_version=${EXISTING_PACKAGE_VERSION:0:5}
  atr_version_with_new_rundeck=4.1.0
  echo "EXISTING_PACKAGE_VERSION: ${current_atr_version}"
  if [[ ((${current_atr_version} < ${atr_version_with_new_rundeck})) ]]
  then
    docker inspect atr-postgres >/dev/null 2>&1
    if [ $? -eq 0 ]; then
      echo "Rundeck tables will be altered in this version."
      # Copy file from dir to postgres container
      docker cp ${DIR}/ansible-scripts/postgres/alter_rundeck_tables.sql atr-postgres:/tmp/alter_rundeck_tables.sql
      # Execute sql script
      docker exec -u postgres -it atr-postgres psql rundeck postgres -f /tmp/alter_rundeck_tables.sql
    else
      echo "atr-postgres container does not exist."
    fi
  else
    echo "Rundeck tables will not be altered in ATR version greater than or equal to 4.1.0."
  fi
fi

deleteOldRabbitmqExchanges

echo
echo "-----------"
echo "Install ATR"
echo "-----------"
ansible_with_bash_fallback "atr/playbook.yml" "ansible-atr.sh"

echo
echo "-----------"
echo "Install Usecase Migration"
echo "-----------"
ansible_with_bash_fallback "usecase-migration/playbook.yml" "ansible-usecase-migration.sh" '--network=atr_net'

echo
echo "-----------"
echo "Install MLCore"
echo "-----------"
ansible_with_bash_fallback "mlcore/playbook.yml" "ansible-mlcore.sh" "--network=atr_net"

echo
echo "-----------"
echo "Install Chatbot"
echo "-----------"
ansible_with_bash_fallback "chatbot/playbook.yml" "ansible-chatbot.sh" '--network=atr_net'


if [ "${PROVISION_DATABASE}" == "true" ]; then
  echo
  echo "-----------"
  echo "Provision databases "
  echo "-----------"
  ansible_with_bash_fallback "mongo-provision/playbook.yml" "ansible-mongo-provision.sh"

  echo
  echo "-----------"
  echo "Provision Rundeck "
  echo "-----------"
  ansible_with_bash_fallback "rundeck-provision/playbook.yml" "ansible-rundeck-provision.sh" '--network=atr_net'
else
  echo
  echo "Skip databases provisioning"
fi

echo
echo "-----------"
echo "Install Ticket Assignment"
echo "-----------"
ansible_with_bash_fallback "ticket-assignment/playbook.yml" "ansible-ticket-assignment.sh" "--network=atr_net"

echo
echo "-----------"
echo "Install Marketplace"
echo "-----------"
ansible_with_bash_fallback "marketplace/playbook.yml" "ansible-marketplace.sh" '--network=atr_net'

# This is applicable on for version < 4.3.0
if [[ ((${atr_current_version} < ${new_atr_version})) ]]; then
  sed -i "s/$existing_es_password/$complex_password/g" ${INSTALLATION_FOLDER}/.atr.properties_tmp
fi

mv "${INSTALLATION_FOLDER}/.atr.properties_tmp" "${INSTALLATION_FOLDER}/.atr.properties"

# This is applicable on for version < 4.3.0
if [[ ((${atr_current_version} < ${new_atr_version})) ]]; then

  echo
  echo "-----------"
  echo "Recreate elasticsearch"
  echo "-----------"
  cd ${INSTALLATION_FOLDER}/utils
  
  ./reverse_container.sh elasticsearch > es_recreate.sh

  sed -i "s/$existing_es_password/$complex_password/g"  es_recreate.sh

  chmod 755 es_recreate.sh

  docker stop elasticsearch

  docker rm elasticsearch 
  echo "-------------"
  echo "ElasticSearch recreation Start"
  echo "-------------"

  ./es_recreate.sh | echo "Wait for ES to be up"

  sleep 60s
  
  docker exec elasticsearch sh -c "./replace.sh $complex_password"

  rm -f es_recreate.sh

  echo "-------------"
  echo "ElasticSearch is recreated"
  echo "-------------"
fi
#end of fix

if [ "${ATR_SERVICE_ENABLED}" == true ]; then
  echo
  echo "-----------"
  echo "Register ATR service in systemd "
  echo "-----------"
  ${UTILS_DIR}/systemd/register.sh ${INSTALLATION_FOLDER} ${UTILS_DIR}/systemd
elif test -f /etc/systemd/system/atr.service; then
  systemctl disable /etc/systemd/system/atr.service
  rm -f /etc/systemd/system/atr.service
fi

function encrypt {
  local file=$1
  local pwd=$2
  out=$(openssl enc -aes-256-cbc -salt -a -in "${file}" -pass "pass:${pwd}" -out "${file}.enc")
  if [ $? -ne 0 ]; then
    echo "Failed to encrypt property file ${file}"
    echo ${out}
    exit -1
  else
    rm -f ${file}
  fi
}

echo "Restarting all Containers"
docker restart $(docker ps -aq)

function restart_containers {
  echo
  echo "--------------------"
  echo "Restarting TM & AQE containers "
  echo "--------------------"
  docker restart ticket-management
  docker restart automation-queue
}


echo
echo "-----------"
echo "Remove deprecated "
echo "-----------"
ansible_with_bash_fallback "clean-olds/playbook.yml" "ansible-clean-olds.sh" '--network=atr_net'


if [ "${VAULT_ENABLED}" == 'true' ]; then
  echo
  echo "-----------"
  echo "Encrypt property installation files "
  echo "-----------"
  encrypt ${INSTALLATION_FOLDER}/.atr.properties ${PROPERTIES_ENCRYPTION_PASSWORD}
  encrypt ${INSTALLATION_FOLDER}/.vault.properties ${PROPERTIES_ENCRYPTION_PASSWORD}
fi

rm -f ${ENV_FILE}
rm -f ${ANSIBLE_ENV_FILE}

# Copy across build.properties file for versioning installations
cp "${DIR}/build.properties" "${INSTALLATION_FOLDER}/build.properties"

restart_containers

# Print instance information
echo
echo
echo "All done!"
echo
echo "If your certificate is a self-signed (default installation), please also accept the certificate on your browser when you connect to:"
echo " - https://${NAMESPACE}/"
echo
echo "Your endpoints for atr are the following:"
echo " - https://${NAMESPACE}/atr                         : Ticket management interface ( admin / ${ADMIN_PASSWORD} )"
echo " - https://${NAMESPACE}/rundeck                     : Rundeck interface ( admin / ${RUNDECK_PASSWORD} )"
echo " - https://${NAMESPACE}/atr-gateway/swagger-ui.html : Swagger api interface ( admin / ${ADMIN_PASSWORD} )"
echo ""
echo "Your default remote worker for ATR is: default-worker / ${WORKER_PASSWORD}"

if [ "${ENCRYPTION_ENABLED}" == 'true' ]; then
echo
echo "Your random volumes LUKS encryption key is ${ENCRYPTION_KEY}"
fi
echo
if [ "${VAULT_ENABLED}" == 'true' ]; then
echo "Your property file encryption key is ${PROPERTIES_ENCRYPTION_PASSWORD}, you will need it to upgrade using the same properties you used"
echo
fi
echo "If you encounter any problem, please send the full installation.log file to the support team. Thanks."
