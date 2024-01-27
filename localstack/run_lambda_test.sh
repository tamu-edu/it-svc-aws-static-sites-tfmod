#!/usr/bin/env bash

if [[ "$1" == "-h" ]]
then
    echo "Usage: $0 <lambda name>"
    exit 1
fi

if ! docker ps | grep localstack > /dev/null
then
    echo "LocalStack container is not running... did you run a docker compose up?"
    exit 1
fi

if ! which tflocal > /dev/null
then
    echo "You must activate a local venv to get tflocal... exiting"
    exit 2
fi

LAMBDA_NAME="LambdaEdgeRewriteFunction-dev"
if [ ! -z "$1" ]
then
    LAMBDA_NAME="$1"
fi


SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
TESTING_DIR="${SCRIPT_DIR}/testing_dir"
TERRAFORM_DIR=$(realpath "${SCRIPT_DIR}/..")

if [ -d $TESTING_DIR ]
then
    rm -rf $TESTING_DIR
fi

mkdir $TESTING_DIR
cp ${TERRAFORM_DIR}/lambda.tf ${TESTING_DIR}/
cp -r ${TERRAFORM_DIR}/LambdaEdgeFunctions ${TESTING_DIR}/
cd $TESTING_DIR
cat <<EOF > "${TESTING_DIR}/main.tf"
provider "aws" {

  access_key = "test"
  secret_key = "test"
  region     = "us-east-1"
}
EOF

cat <<EOF > "${TESTING_DIR}/variables.tf"
variable "deployment" {
    type    = string
    default = "dev"
}

variable "log_expiration" {
    type    = number
    default = 365
}
EOF
 
echo "Creating LocalStack resources"
tflocal init
tflocal apply -auto-approve

let SUCCESS=1
cd "${SCRIPT_DIR}/tests"
./tester.py $LAMBDA_NAME
if [ $? -gt 0 ]
then
    let SUCCESS=0
fi

# Tear down our localstack resources
echo "Destroying LocalStack resources"
cd $TESTING_DIR
tflocal destroy -auto-approve


if [ $SUCCESS -eq 0 ]
then
    exit 1
fi