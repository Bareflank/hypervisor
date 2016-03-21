#!/bin/bash -e

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
# Checks
# ------------------------------------------------------------------------------

if [ ! -d "bfelf_loader" ]; then
    echo "The 'setup-ubuntu.sh' script must be run from the bareflank repo's root directory"
    echo $PWD
    exit 1
fi

# ------------------------------------------------------------------------------
# Install Packages
# ------------------------------------------------------------------------------

case $(lsb_release -sr) in
15.10)
    ;;
*)
    if [ -z "$SILENCE" ]; then
        read -p "This script will update GCC to version 5.2. Continue? [y/n]: " -n 1 -r
        if [[ $REPLY =~ ^[Yy]$ ]]
        then
            echo
        else
            echo
            exit 1
        fi
    fi
    sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
    sudo apt-get update
    sudo apt-get install g++-5 --force-yes
    sudo rm /usr/bin/gcc
    sudo rm /usr/bin/g++
    sudo ln -s /usr/bin/gcc-5 /usr/bin/gcc
    sudo ln -s /usr/bin/g++-5 /usr/bin/g++
    gcc --version
    g++ --version
    ;;
esac

sudo apt-get install build-essential libgmp-dev libmpc-dev libmpfr-dev libisl-dev flex bison nasm texinfo -y

# ------------------------------------------------------------------------------
# Create Cross Compiler
# ------------------------------------------------------------------------------

./tools/scripts/create-cross-compiler.sh
