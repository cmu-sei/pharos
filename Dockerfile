FROM ubuntu:latest

RUN apt-get -y update \
&&  apt-get -y install sudo build-essential wget flex ghostscript bzip2 git subversion automake libtool bison python libncurses-dev vim-common sqlite3 libsqlite3-dev zlib1g-dev cmake libyaml-cpp-dev libboost-all-dev libxml2-dev \
&&  rm -rf /var/lib/apt/lists/*

ARG NCPU=1
ENV NCPU=$NCPU

ADD . /root/pharos

# Put everything in the same layer so it's much smaller
RUN /root/pharos/scripts/build.bash -reclaim && \
  find /usr/local/lib /usr/local/bin | xargs file | grep 'current ar archive' | awk -F':' '{print $1}' | xargs strip
