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

if [[ ! -d "$BUILD_ABS/source_libbfc" ]]; then
    $BUILD_ABS/build_scripts/fetch_libbfc.sh $BUILD_ABS
fi

rm -Rf $BUILD_ABS/build_libbfc
mkdir -p $BUILD_ABS/build_libbfc

pushd $BUILD_ABS/build_libbfc

cp -Rf $BUILD_ABS/source_libbfc/sysctl.h $BUILD_ABS/sysroot/x86_64-elf/include/sys/
cp -Rf $BUILD_ABS/source_libbfc/pthread.h $BUILD_ABS/sysroot/x86_64-elf/include/

flags="-DSYM_PROVIDED__WRITE -DSYM_PROVIDED__MALLOC -DSYM_PROVIDED__FREE -DSYM_PROVIDED__CALLOC -DSYM_PROVIDED__FSTAT -DSYM_PROVIDED__REALLOC -DLOOKUP_TLS_DATA"

if [[ $compiler == *"clang"* ]]; then
    cc="$BUILD_ABS/build_scripts/x86_64-bareflank-clang $flags"
    cxx="$BUILD_ABS/build_scripts/x86_64-bareflank-clang++ $flags"
    ar="$BUILD_ABS/build_scripts/x86_64-bareflank-ar"
else
    cc="$BUILD_ABS/build_scripts/x86_64-bareflank-gcc $flags"
    cxx="$BUILD_ABS/build_scripts/x86_64-bareflank-g++ $flags"
    ar="$BUILD_ABS/build_scripts/x86_64-bareflank-ar"
fi

$cc $CFLAGS -c $BUILD_ABS/source_libbfc/*.c
$cxx $CXXFLAGS -c $BUILD_ABS/source_libbfc/*.cpp
$BUILD_ABS/build_scripts/x86_64-bareflank-clang -shared *.o -o libbfc.so
mv libbfc.so $BUILD_ABS/sysroot/x86_64-elf/lib/

popd
