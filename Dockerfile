FROM ubuntu:latest

RUN apt-get -y update && apt-get -y install sudo build-essential wget flex ghostscript bzip2 git subversion automake libtool bison python libncurses5-dev vim-common libsqlite3-0 libsqlite3-dev zlib1g-dev

ADD . /root/pharos

RUN /root/pharos/scripts/build.bash -reclaim && \
 rm -rf /root/pharos && \
 cd /usr/local/lib && \
 find /usr/local/lib | xargs file | grep 'current ar archive' | awk -F':' '{print $1}' | xargs strip
