#!/bin/bash

set -x
git pull

source /etc/os-release

git checkout ${VERSION_CODENAME}

autoreconf --install
./configure --with-nagios-plugins=${NP_PATH} \
    --prefix=/usr/local/nagios \
    --sysconfdir=/usr/local/nagios/etc \
    --libexecdir=/usr/local/nagios/libexec
make install-groups-users
make deb
mv *.deb /usr/src/${VERSION_CODENAME}/
