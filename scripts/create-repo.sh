#!/bin/bash

set -x

do_hash() {
    HASH_NAME=$1
    HASH_CMD=$2
    echo "${HASH_NAME}:"
    for f in $(find -type f); do
        f=$(echo $f | cut -c3-) # remove ./ prefix
        if [ "$f" = "Release" ]; then
            continue
        fi
        echo " $(${HASH_CMD} ${f}  | cut -d" " -f1) $(wc -c $f)"
    done
}

if [ ! -d gpg ]; then
    mkdir gpg
fi
CURDIR=$(pwd)
export GNUPGHOME="$(mktemp -d ${CURDIR}/gpg/pgpkeys-XXXXXX)"

gpg --list-keys SamanaMonitor > /dev/null 2>&1
if [ "0" != "$?" ]; then
    if [ ! -f gpg/pgp-key.private ]; then
        echo "Add private key to gpg directory" >&2
        exit 1
    fi
    cat gpg/pgp-key.private | gpg --import
fi


DIST="bionic"
for d in ${DIST}; do
    mkdir -p apt-repo/pool/main/${d}
    mkdir -p apt-repo/dists/${d}/main/binary-amd64
    mv $d/*.deb apt-repo/pool/main/${d}
    cd apt-repo
    dpkg-scanpackages --arch amd64 pool/ > dists/${d}/main/binary-amd64/Packages
    cat dists/${d}/main/binary-amd64/Packages | gzip -9 > dists/${d}/main/binary-amd64/Packages.gz
    cd dists/${d}
    cat << EOF > Release
Origin: Samana Monitor Repository
Label: SAMM
Suite: ${d}
Codename: ${d}
Version: 1.0.0
Architectures: amd64
Components: main
Description: SAMM Samana Advanced Monitoring and Management repository
Date: $(date -Ru)
EOF
    do_hash "MD5Sum" "md5sum" >> Release
    do_hash "SHA1" "sha1sum" >> Release
    do_hash "SHA256" "sha256sum" >> Release
    cat Release | gpg --default-key SamanaMonitor -abs > Release.gpg
    cat Release | gpg --default-key SamanaMonitor -abs --clearsign > InRelease
    cd ${CURDIR}
done
