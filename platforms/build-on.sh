#!/usr/bin/env bash

set -eu

cd "$(dirname "$0")"
project_dir=$(dirname "$(pwd)")
project_name=$(basename "$project_dir")
parent_dir=$(dirname "$project_dir")

MOUNT_POINT=/mnt/sources
WORKING_DIR="$MOUNT_POINT/$project_name"

dockerfile=$1
if [ ! -f "$dockerfile" ]; then
    dockerfile="$1.dockerfile"
    if [ ! -f "$dockerfile" ]; then
        echo "Platform not found: $1"
        echo "To add a platform, create $1.dockerfile"
        exit 1
    fi
fi

docker build -t rust-rhel - < "$dockerfile"
docker run -v "$parent_dir":"$MOUNT_POINT" -w "$WORKING_DIR" -it rust-rhel
