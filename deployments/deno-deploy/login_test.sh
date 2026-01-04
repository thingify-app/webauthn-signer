#!/bin/bash

BASE_URL="http://localhost:8000"

NONCE=$(curl -X POST "${BASE_URL}/createAccountInitial" | jq -r '.nonce')

curl -X POST -H "Content-Type: application/json" \
    -d '{"nonce": "'${NONCE}'", "username": "foobar", "keyId": "foobar==", "publicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEyhh6vTOFDDnJPn1fJffrz7lk8rFSwrxYnnSD03mIZ+8I1sxQEXyiVvV0fYuWPJ8He2szUGUX33JOI2ru89sI5w=="}' \
    "${BASE_URL}/createAccount"
