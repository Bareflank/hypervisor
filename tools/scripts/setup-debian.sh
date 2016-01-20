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
  exec 1>~/setup-cygwin_stdout.log
  exec 2>~/setup-cygwin_stderr.log
fi

# ------------------------------------------------------------------------------
# Checks
# ------------------------------------------------------------------------------

if [ ! -d "bfelf_loader" ]; then
    echo "The 'setup-debian.sh' script must be run from the bareflank repo's root directory"
    echo $PWD
    exit 1
fi

# ------------------------------------------------------------------------------
# Install Packages
# ------------------------------------------------------------------------------

sudo apt-get install build-essential libgmp-dev libmpc-dev libmpfr-dev libisl-dev flex bison nasm texinfo -y

# ------------------------------------------------------------------------------
# Create Cross Compiler
# ------------------------------------------------------------------------------

./tools/scripts/create-cross-compiler.sh
