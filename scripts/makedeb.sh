#!/bin/bash

make dist
CURDIR=$(pwd)
BUILDDEV=$(mkdir -d)
cp samana-check-winrm-1.0.tar.gz ${BUILDDEV}
cd ${BUILDDEV}
tar -xzvf samana-check-winrm-1.0.tar.gz
cd samana-check-winrm-1.0
debmake
cp scripts/configuressl.sh debian/postinst
TAB=$(printf "\t")
cat <<EOF >> debian/rules
export NP_PATH=../../nagios-plugins
override_dh_usrlocal:
override_dh_auto_configure:
${TAB}dh_auto_configure -- --prefix=/usr/local/nagios
EOF
sed -i -e "s/^\(Depends.*\)/\1, gss-ntlmssp (>= 0.7.0)/" debian/control
debuild
cp ../samana-check-winrm_1.0-1_amd64.deb ${CURDIR}
rm -Rf ${BUILDDEV}