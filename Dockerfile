FROM ubuntu:latest

ADD . /root/pharos

RUN apt-get -y update
RUN apt-get -y install sudo build-essential wget flex ghostscript bzip2 git subversion automake libtool bison python libncurses5-dev vim-common libsqlite3-0 libsqlite3-dev

RUN /root/pharos/scripts/build.bash


