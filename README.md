# Packages needed to compile
* gcc
* make
* libxml2-dev
* libssl-dev
* libcurl4-openssl-dev
* gss-ntlmssp-dev
* uuid-dev
* libkrb5-dev
* automake
* debhelper
* debmake
```
apt update
apt upgrade -y
apt install -y gcc make libxml2-dev libssl-dev \
    libcurl4-openssl-dev gss-ntlmssp-dev uuid-dev libkrb5-dev \
    automake debhelper debmake
```

# Packages needed to run
* libxml2
* libcurl4
* gss-ntlmssp
```
apt install -y libxml2 libcurl4 gss-ntlmssp
```

# Edit openssl.cnf to enable legacy rc4 for ntlm encryption
This is already part of the script ```scripts/configuressh.sh```
```
sed -i -e '/default = default_sect/alegacy = legacy_sect\n' \
    -e '/\[default_sect\]/a activate = 1\n\n[legacy_sect]\nactivate = 1\n' \
    /etc/ssl/openssl.cnf
```

# Create debian package
Based on:
https://www.debian.org/doc/manuals/debmake-doc/ch04.en.html
```
DEBEMAIL=info@samanagroup.com ./scripts/makedeb.sh /usr/src/nagios-plugins
```