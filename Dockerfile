FROM ubuntu:latest

RUN (apt-get -y update && apt-get upgrade -y)
RUN (apt-get -y install sudo build-essential wget flex ghostscript bzip2 git subversion automake libtool bison python libncurses5-dev vim-common libsqlite3-0 libsqlite3-dev)

COPY ./ /usr/local/src/pharos

# Put everyting in the same layer.  Otherwise when we strip the layer is still 1.7GB
RUN (/usr/local/src/pharos/scripts/build.bash && \
rm -rf /usr/local/src/pharos && \
cd /usr/local/lib && \
find /usr/local/lib | xargs file | grep 'current ar archive' | awk -F':' '{print $1}' | xargs strip && \
find /usr/local/lib | xargs file | grep ELF | awk -F':' '{print $1}' | xargs strip && \
find /usr/local/bin | xargs file | grep ELF | awk -F':' '{print $1}' | xargs strip )
