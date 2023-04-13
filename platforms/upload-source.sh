#!/usr/bin/env bash

set -eu

cd "$(dirname "$0")"
cd ..
project_name=$(pwd)
destination=$1
git ls-files | tar Tzcf - "$project_name.tgz"

cd ../aya
git ls-files | tar Tzcf - "../aya.tgz"

scp ../*.tgz "$destination":~/
