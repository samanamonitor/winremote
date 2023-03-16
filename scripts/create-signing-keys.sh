#!/bin/bash

mkdir gpg
echo "%echo Generating an Samana Monitor signing key
Key-Type: RSA
Key-Length: 4096
Name-Real: SamanaMonitor
Name-Email: info@samanagroup.com
Expire-Date: 0
%no-ask-passphrase
%no-protection
%commit" > gpg/samm-pgp-key.batch

export GNUPGHOME="$(mktemp -d gpg/pgpkeys-XXXXXX)"
gpg --no-tty --batch --gen-key gpg/samm-pgp-key.batch
gpg --armor --export SamanaMonitor > gpg/pgp-key.public
gpg --armor --export-secret-keys SamanaMonitor > gpg/pgp-key.private
