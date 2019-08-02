#!/bin/bash

set -x

script_dir=$(dirname $0)

cd ${script_dir}/..
dep ensure
CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o kube-mutating-webhook .
docker build --no-cache -t 783721547467.dkr.ecr.us-east-1.amazonaws.com/jenkins-executor-helpers:cloudbees-fixer .

docker push 783721547467.dkr.ecr.us-east-1.amazonaws.com/jenkins-executor-helpers:cloudbees-fixer
