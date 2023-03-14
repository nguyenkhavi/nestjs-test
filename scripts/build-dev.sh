#!/bin/bash

echo "CURRENT BRANCH $1"
git checkout $1 
git pull -r 
curl \
    --header "X-Vault-Token: $2" \
    $3/v1/kv/data/web3asy-proxy \
| jq ".data.data" | jq -r 'to_entries|map("\(.key)=\"\(.value|tostring)\"")|.[]' > .env
cd ..
docker compose up --build -d proxy