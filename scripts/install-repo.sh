#!/bin/bash

. /etc/os-release

apt update
apt upgrade -y
apt install -y ca-certificates wget
mkdir -p /var/lib/samana
wget -O /var/lib/samana/pgp-samm-key.public https://samm-repo.s3.amazonaws.com/pgp-samm-key.public
echo "deb [arch=amd64 signed-by=/var/lib/samana/pgp-samm-key.public] https://samm-repo.s3.amazonaws.com ${UBUNTU_CODENAME} main" > /etc/apt/sources.list.d/samm.list
apt update
