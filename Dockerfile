FROM ubuntu:latest

ARG NCPU=1
ENV NCPU=$NCPU

# This will reduce the memory usage by default
ARG CXXFLAGS="--param ggc-min-expand=5 --param ggc-min-heapsize=32768"
ENV CXXFLAGS="$CXXFLAGS"

# This will make a smaller, non-development Dockerfile by default
ARG RECLAIM="-reclaim"

RUN DEBIAN_FRONTEND=noninteractive apt-get -y update && DEBIAN_FRONTEND=noninteractive apt-get -y install sudo build-essential wget flex ghostscript bzip2 git subversion automake libtool bison python3 python3-distutils libncurses-dev vim-common sqlite3 libsqlite3-0 libsqlite3-dev zlib1g-dev cmake ninja-build libyaml-cpp-dev libboost-dev libboost-chrono-dev libboost-filesystem-dev libboost-iostreams-dev libboost-program-options-dev libboost-random-dev libboost-regex-dev libboost-system-dev libboost-wave-dev libboost-thread-dev libboost-timer-dev libxml2-dev && rm -rf /var/lib/apt/lists/*

# Only add the build prerequisites script so they won't be rebuilt on pharos code change
RUN mkdir -p /root/pharos/scripts/
ADD scripts/build_prereqs.bash /root/pharos/scripts/
RUN /root/pharos/scripts/build_prereqs.bash $RECLAIM

ADD . /root/pharos

# Put everything in the same layer so it's much smaller
RUN /root/pharos/scripts/build.bash $RECLAIM && \
  find /usr/local/lib /usr/local/bin | xargs file | grep 'current ar archive' | awk -F':' '{print $1}' | xargs strip
