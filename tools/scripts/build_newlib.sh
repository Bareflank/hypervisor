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
rm -Rf $BUILD_ABS/sysroot/x86_64-elf/lib
rm -Rf $BUILD_ABS/sysroot/x86_64-elf/include/
mkdir -p $BUILD_ABS/build_newlib

pushd $BUILD_ABS/build_newlib

export PATH="$HOME/compilers/$compiler/bin:$PATH"

if [[ $compiler == *"clang"* ]]; then
    cc="$BUILD_ABS/build_scripts/x86_64-bareflank-clang"
    cxx="$BUILD_ABS/build_scripts/x86_64-bareflank-clang++"
    ar="$BUILD_ABS/build_scripts/x86_64-bareflank-ar"
else
    cc="$BUILD_ABS/build_scripts/x86_64-bareflank-gcc"
    cxx="$BUILD_ABS/build_scripts/x86_64-bareflank-g++"
    ar="$BUILD_ABS/build_scripts/x86_64-bareflank-ar"
fi

echo "Building newlib. Please wait..."
../source_newlib/configure --target=x86_64-elf --disable-libgloss AR_FOR_TARGET="$ar" CC_FOR_TARGET="$cc" CXX_FOR_TARGET="$cxx" CFLAGS_FOR_TARGET="$CFLAGS" CXXFLAGS_FOR_TARGET="$CXXFLAGS" --prefix=$BUILD_ABS/sysroot/ 1>/dev/null 2>/dev/null
make -j2 1>/dev/null 2>/dev/null
make -j2 install 1>/dev/null 2>/dev/null

$BUILD_ABS/build_scripts/x86_64-bareflank-clang -shared `find $BUILD_ABS/build_newlib/x86_64-elf/newlib/libc -name "*.o" | xargs echo` -o libc.so
mv libc.so $BUILD_ABS/sysroot/x86_64-elf/lib/

popd
