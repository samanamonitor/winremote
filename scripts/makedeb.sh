#!/bin/bash

set -ex

NP_PATH=$1

if [ -z "${NP_PATH}" ]; then
    echo "Please provide nagios-plugins source code path" >&2
    exit 1
fi

if [ ! -d ${NP_PATH} ]; then
    echo "NP_PATH ${NP_PATH} is not a directory." >&2
    exit 1
fi

make dist
CURDIR=$(pwd)
BUILDDEV=$(mktemp -d)
cp samana-check-winrm-1.0.tar.gz ${BUILDDEV}
cd ${BUILDDEV}
tar -xzvf samana-check-winrm-1.0.tar.gz
cd samana-check-winrm-1.0
debmake
cp scripts/configuressl.sh debian/postinst
TAB=$(printf "\t")
cat <<EOF >> debian/rules
export NP_PATH=${NP_PATH}
override_dh_usrlocal:
override_dh_auto_configure:
${TAB}dh_auto_configure -- --prefix=/usr/local/nagios
EOF
sed -i -e "s/^\(Depends.*\)/\1, gss-ntlmssp (>= 0.7.0)/" debian/control
debuild
cp ${BUILDDEV}/samana-check-winrm_1.0-1_amd64.deb ${CURDIR}
rm -Rf ${BUILDDEV}