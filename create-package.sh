#!/bin/bash

set -ex

UBUNTU_VERSION=$1
NP_PATH=$2
DEST_PATH=$3

usage() {
    echo $1 >&2
    echo "$0 <ubuntu version code> <path to nagios-plugins> [ <path to store deb package> ]" >&2
    exit 1
}

if [ -z "${UBUNTU_VERSION}" ]; then
    usage "Must define Ubuntu version code. e.g. jammy"
fi

if [ -z "${NP_PATH}" ]; then
    usage "Must specify path to nagios-plugins libraries"
fi

if [ -z "${DEST_PATH}" ]; then
    DEST_PATH=$(pwd)/${UBUNTU_VERSION}
fi

if [ -d ${DEST_PATH} ]; then
    rm -Rf ${DEST_PATH}
fi
mkdir -p ${DEST_PATH}
id=$(docker image ls -q winremote:${UBUNTU_VERSION})
if [ -z "$id" ]; then
    docker build -t winremote:${UBUNTU_VERSION} --build-arg UBUNTU_VERSION=${UBUNTU_VERSION} .
fi
docker run -it --name build-winremote \
    --mount type=bind,source=${NP_PATH},target=/usr/src/nagios-plugins \
    --mount type=bind,source=${DEST_PATH},target=/usr/src/${UBUNTU_VERSION} \
    --rm winremote:${UBUNTU_VERSION} ./build-deb.sh
