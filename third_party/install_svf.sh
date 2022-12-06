#!/bin/bash

function addToPATH {
  case ":$PATH:" in
    *":$1:"*) :;; # already there
    *) PATH="$1:$PATH";; # or PATH="$PATH:$1"
  esac
}

# Get SVF
if [ ! -d SVF ]; then
	git clone https://github.com/SVF-tools/SVF
	cd SVF && git reset --hard a99ee34 && cd -
	cp `pwd`/../patches/svf/setup.sh ./SVF/setup.sh
	cp `pwd`/../patches/svf/build.sh ./SVF/build.sh

	# Link SVF-specific files
	rm ./SVF/tools/Example/svf-ex.cpp
	ln -s `pwd`/../patches/svf/svf-ex.cpp SVF/tools/Example/svf-ex.cpp

	rm ./SVF/include/Graphs/GenericGraph.h
	ln -s `pwd`/../patches/svf/GenericGraph.h SVF/include/Graphs/GenericGraph.h

	rm ./SVF/tools/Example/CMakeLists.txt
	cp `pwd`/../patches/svf/CMakeLists.txt SVF/tools/Example/CMakeLists.txt

	ln -s `pwd`/../patches/svf/fence.cpp SVF/tools/Example/fence.cpp
	ln -s `pwd`/../patches/svf/util.cpp SVF/tools/Example/util.cpp
	ln -s `pwd`/../patches/svf/svf-af.h SVF/include/svf-af.h

	if [ ! -d spdlog ]; then
		git clone https://github.com/gabime/spdlog 
	fi
	cp -r spdlog/include/spdlog/ ./SVF/include
	cd SVF && source ./build.sh && cd -
else
	cd SVF && source ./setup.sh && cd -
fi

# Get gllvm
which go
if [ $? -eq 0 ]; then
	echo "Go already present, not downloading"
else
	if [ ! -f go1.14.4.linux-amd64.tar.gz ]; then
		wget https://dl.google.com/go/go1.14.4.linux-amd64.tar.gz
	fi

    if [ "$EUID" -ne 0 ]; then
	    sudo tar -C /usr/local -xzf go1.14.4.linux-amd64.tar.gz
    else
	    tar -C /usr/local -xzf go1.14.4.linux-amd64.tar.gz
    fi
    
	addToPATH /usr/local/go/bin
	export GOPATH=$PWD
	go get github.com/SRI-CSL/gllvm/cmd/...
	addToPATH $GOPATH/bin
fi
