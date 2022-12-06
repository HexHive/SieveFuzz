FROM zjuchenyuan/base

RUN apt update && \
    apt install -y \
    # Additional QoL and eval-specific packages
    silversearcher-ag beanstalkd gdb screen patchelf apt-transport-https ca-certificates \
    # CGC-specific requirements 
    g++-multilib gcc-multilib lib32z1-dev\
    # Fuzz-target requirements
    libpcap-dev libsdl-dev libfreetype6-dev\
    # AFLGo-specific requirements
    sudo curl wget build-essential make cmake ninja-build git subversion python2.7 binutils-gold binutils-dev python-dev python3 python3-dev python3-pip autoconf automake libtool-bin python-bs4 libclang-4.0-dev gawk pkg-config &&\
    python3 -m pip install --upgrade pip && python3 -m pip install networkx pydot pydotplus greenstalk psutil scipy tabulate matplotlib

# Add updated gcc compiler for SVF
RUN add-apt-repository ppa:ubuntu-toolchain-r/test && \
    apt-get update && \
    apt-get install -y gcc-7 g++-7

# Add Clang-9
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key| apt-key add - &&\
    apt-get update && \
    apt-add-repository "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-9 main" && \ 
    apt-get update && \
    apt-get install -y clang-9 libclang-9-dev

RUN apt-get -y install locales && locale-gen en_US.UTF-8
ENV LC_ALL="en_US.UTF-8"

# Setup SieveFuzz
WORKDIR /root
RUN mkdir areafuzz
COPY . ./areafuzz
WORKDIR ./areafuzz
RUN ./build.sh

# Setup gllvm
COPY ./gllvm_bins/ /root/areafuzz/third_party/SVF/Release-build/bin/
