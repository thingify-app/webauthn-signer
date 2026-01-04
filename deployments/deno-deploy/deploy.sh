#!/bin/bash

TEMP_DIR=$(mktemp -d)

echo "Preparing deployment package in ${TEMP_DIR}"

cp -r . "${TEMP_DIR}"

# Hacks to make deno deploy allow local module imports.
cp -r ../../server/ "${TEMP_DIR}/server"
sed -i 's|"../../server/src/index.ts"|"./server/src/index.ts"|g' "${TEMP_DIR}/deno.json"

cd "${TEMP_DIR}"
deno deploy --prod
