#!/bin/bash -e

# ------------------------------------------------------------------------------
# Checks
# ------------------------------------------------------------------------------

sudo dnf install -y redhat-lsb-core

case $(lsb_release -si) in
Fedora)
    ;;
*)
    echo "This script can only be used with: Fedora"
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
  exec 1>~/setup-fedora_stdout.log
  exec 2>~/setup-fedora_stderr.log
fi

# ------------------------------------------------------------------------------
# Install Packages
# ------------------------------------------------------------------------------

case $(lsb_release -sr) in
24)
    ;&

23)
    ;&

22)

    sudo dnf groupinstall -y "Development Tools"
    sudo dnf install -y gcc-c++
    sudo dnf install -y gmp-devel
    sudo dnf install -y libmpc-devel
    sudo dnf install -y mpfr-devel
    sudo dnf install -y isl-devel
    sudo dnf install -y cmake
    sudo dnf install -y nasm
    sudo dnf install -y texinfo
    sudo dnf install -y libstdc++-static
    sudo dnf install -y kernel-devel
    sudo dnf install -y kernel-headers
    sudo dnf update -y kernel

    ;;

*)
    echo "This version of Fedora is not supported"
    exit 1

esac

# ------------------------------------------------------------------------------
# Create Cross Compiler
# ------------------------------------------------------------------------------

./tools/scripts/create-cross-compiler.sh

# ------------------------------------------------------------------------------
# Reboot
# ------------------------------------------------------------------------------

echo "WARNING: A reboot is required before you can build the hypervisor!!!!!"
