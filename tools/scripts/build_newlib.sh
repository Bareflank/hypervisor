#!/bin/bash -e
#
# Bareflank Hypervisor
#
# Copyright (C) 2015 Assured Information Security, Inc.
# Author: Rian Quinn        <quinnr@ainfosec.com>
# Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

%ENV_SOURCE%

if [[ -f /.dockerenv ]]; then
    HOME=/tmp
fi

if [[ ! -d "$BUILD_ABS/source_newlib" ]]; then
    $BUILD_ABS/build_scripts/fetch_newlib.sh $BUILD_ABS
fi

rm -Rf $BUILD_ABS/build_newlib
mkdir -p $BUILD_ABS/build_newlib

pushd $BUILD_ABS/build_newlib

export NEWLIB_DEFINES="-D_HAVE_LONG_DOUBLE -D_LDBL_EQ_DBL -D_POSIX_TIMERS -U__STRICT_ANSI__ -DMALLOC_PROVIDED"
export CFLAGS="-fpic -ffreestanding -mno-red-zone $NEWLIB_DEFINES"
export CXXFLAGS="-fno-use-cxa-atexit -fno-threadsafe-statics $CFLAGS"

export PATH="$HOME/compilers/$compiler/bin:$PATH"

echo "Building newlib. Please wait..."
../source_newlib/configure --target=x86_64-elf --prefix=$BUILD_ABS/sysroot/ 1>/dev/null 2>/dev/null
make -j2 1>/dev/null 2>/dev/null
make -j2 install 1>/dev/null 2>/dev/null

popd
