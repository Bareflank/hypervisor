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

if [[ "$SYSROOT_NAME" == "vmm" ]]; then
    CFLAGS="$CFLAGS -DMALLOC_PROVIDED"
fi

if [[ ! -d "$BUILD_ABS/source_newlib" ]]; then
    $BUILD_ABS/build_scripts/fetch_newlib.sh $BUILD_ABS
fi

rm -Rf $BUILD_ABS/build_newlib
mkdir -p $BUILD_ABS/build_newlib

pushd $BUILD_ABS/build_newlib

export PATH=$BUILD_ABS/build_scripts:$PATH

echo "Building newlib. Please wait..."
../source_newlib/configure --target=x86_64-$SYSROOT_NAME-elf CC_FOR_TARGET=x86_64-$SYSROOT_NAME-clang CXX_FOR_TARGET=x86_64-$SYSROOT_NAME-clang++ CFLAGS_FOR_TARGET="$CFLAGS" CXXFLAGS_FOR_TARGET="$CXXFLAGS" --prefix=$BUILD_ABS/sysroot_$SYSROOT_NAME/ --disable-libgloss --disable-multilib --enable-newlib-multithread --enable-newlib-iconv --disable-newlib-supplied-syscalls 1>/dev/null 2>/dev/null
make -j2 1>/dev/null 2>/dev/null
make -j2 install 1>/dev/null 2>/dev/null

#
# HACK:
#
# The following creates a shared library for newlib because it refuses to
# create a shared library unless the target is Linux. Because of this, we
# create the shared library ourselves.
#

x86_64-$SYSROOT_NAME-clang -shared `find $BUILD_ABS/build_newlib/x86_64-$SYSROOT_NAME-elf/newlib/libc -name "*.o" | xargs echo` -o libc.so
mv libc.so $BUILD_ABS/sysroot_$SYSROOT_NAME/x86_64-$SYSROOT_NAME-elf/lib/

popd
