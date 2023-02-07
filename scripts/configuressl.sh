#!/bin/sh

if ! grep -q "legacy_sect" /etc/ssl/openssl.cnf; then
    sed -i -e '/default = default_sect/alegacy = legacy_sect\n' \
        -e '/\[default_sect\]/a activate = 1\n\n[legacy_sect]\nactivate = 1\n' \
        /etc/ssl/openssl.cnf
fi
