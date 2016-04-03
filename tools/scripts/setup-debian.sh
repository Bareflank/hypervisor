#!/bin/bash -e

# ------------------------------------------------------------------------------
# Checks
# ------------------------------------------------------------------------------

case $(lsb_release -si) in
Debian)
    ;;
*)
    echo "This script can only be used with: Debian"
    exit 1
esac

if [ ! -d "bfelf_loader" ]; then
    echo "This script must be run from bareflank root directory"
    exit 1
fi

# ------------------------------------------------------------------------------
# Silence
# ------------------------------------------------------------------------------

# This is used by Travic CI to prevent this script from overwhelming it's
# output. If there is too much output, Travis CI just gives up. The problem is,
# Travis CI uses output as a means to know that the script has not died. So
# we supress output here, and then use a script in Travis CI to ping it's
# watchdog every so often to keep this script alive.

if [ -n "${SILENCE+1}" ]; then
  exec 1>~/setup-ubuntu_stdout.log
  exec 2>~/setup-ubuntu_stderr.log
fi

# ------------------------------------------------------------------------------
# Install Packages
# ------------------------------------------------------------------------------

case $(lsb_release -sr) in
8.4)
    ;&
8.3)
    ;&
8.2)
    ;&
8.1)
    ;&
8.0)

    if [ -z "$SILENCE" ]; then
        read -r -p "This script will update cmake to version 3.x. Continue? [y/n]: " response
        case $response in
            [yY][eE][sS]|[yY])
                ;;
            *)
                exit 1
                ;;
        esac
    fi

    sudo apt-get install -y --force-yes build-essential
    sudo apt-get install -y --force-yes linux-headers-$(uname -r)
    sudo apt-get install -y --force-yes libgmp-dev
    sudo apt-get install -y --force-yes libmpc-dev
    sudo apt-get install -y --force-yes libmpfr-dev
    sudo apt-get install -y --force-yes libisl-dev
    sudo apt-get install -y --force-yes flex
    sudo apt-get install -y --force-yes bison
    sudo apt-get install -y --force-yes nasm
    sudo apt-get install -y --force-yes texinfo

    rm -Rf $HOME/tmp-dir-cmake
    mkdir $HOME/tmp-dir-cmake
    pushd $HOME/tmp-dir-cmake
    git clone --depth 1 git://cmake.org/cmake.git
    cd cmake
    ./configure
    make -j2
    sudo make -j2 install
    popd
    rm -Rf $HOME/tmp-dir-cmake

    ;;

*)
    echo "This version of Debian is not supported"
    exit 1

esac

# ------------------------------------------------------------------------------
# Create Cross Compiler
# ------------------------------------------------------------------------------

./tools/scripts/create-cross-compiler.sh
