FROM ubuntu:rolling AS buildenv

RUN apt-get -y update \
&&  apt-get -y install sudo build-essential wget flex ghostscript bzip2 git subversion automake xutils-dev libtool bison python libncurses-dev vim-common sqlite3 libsqlite3-dev zlib1g-dev cmake ninja-build libyaml-cpp-dev libboost-all-dev libxml2-dev \
&&  rm -rf /var/lib/apt/lists/*

ARG NCPU=1
ENV NCPU=$NCPU

# only add the script so prereqs won't be rebuilt on pharos code change
ADD scripts/build_prerequisites.bash /root/
RUN /root/build_prerequisites.bash -reclaim

ADD . /root/pharos

# Put everything in the same layer so it's much smaller
RUN /root/pharos/scripts/build.bash -reclaim && \
  find /usr/local/lib /usr/local/bin | xargs file | grep 'current ar archive' | awk -F':' '{print $1}' | xargs strip
