#!/bin/bash

set -euo pipefail
set -x

script_dir=$(dirname $0)

aws eks update-kubeconfig --name ci
kubectl config use-context arn:aws:eks:us-east-1:783721547467:cluster/ci

cat > ${script_dir}/../helm/ca_bundle.yaml <<EOF
---
ca_bundle: $(kubectl config view --raw --minify --flatten -o jsonpath='{.clusters[].cluster.certificate-authority-data}')
EOF

cd ${script_dir}/../helm

COMMAND=${1:-sync}

helm tiller run -- helmfile ${COMMAND}
