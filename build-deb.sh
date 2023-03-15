#!/bin/bash

. /etc/os-release

autoreconf --install
automake
./configure --with-nagios-plugins=${NP_PATH} \
    --prefix=/usr/local/nagios \
    --sysconfdir=/usr/local/nagios/etc \
    --libexecdir=/usr/local/nagios/libexec
make install-groups-users
make deb
mv *.deb /usr/src/${VERSION_CODENAME}/
