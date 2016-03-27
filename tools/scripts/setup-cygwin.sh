#!/bin/bash

echo "Windows is currently not supported"
exit 1

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
    echo "The 'setup-cygwin.sh' script must be run from the bareflank repo's root directory"
    echo $PWD
    exit 1
fi

if [ ! -f /usr/bin/setup-x86_64.exe ]; then
    echo "Cygwin not found: /usr/bin/setup-x64.exe"
    exit
fi

# ------------------------------------------------------------------------------
# Install Packages
# ------------------------------------------------------------------------------

/usr/bin/setup-x86_64.exe -q -P wget make gcc-g++ diffutils libgmp-devel libmpfr-devel libmpc-devel libisl-devel nasm texinfo

# ------------------------------------------------------------------------------
# Create Cross Compiler
# ------------------------------------------------------------------------------

./tools/scripts/create-cross-compiler.sh
