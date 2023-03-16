ARG UBUNTU_VERSION
FROM ubuntu:${UBUNTU_VERSION}
ENV DEBIAN_FRONTEND=noninteractive
ENV NP_PATH=/usr/src/nagios-plugins
ENV UBUNTU_VERSION=${UBUNTU_VERSION}
RUN apt update
RUN apt upgrade -y
RUN apt install -y git gcc make libxml2-dev libssl-dev libcurl4-openssl-dev gss-ntlmssp-dev uuid-dev libkrb5-dev automake debhelper debmake
RUN git clone -b ${UBUNTU_VERSION} https://github.com/samanamonitor/winremote.git /usr/src/winremote
WORKDIR /usr/src/winremote
CMD /bin/bash