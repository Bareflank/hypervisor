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

rm -Rf /tmp/bareflank/build_gcc
mkdir -p /tmp/bareflank/build_gcc

pushd /tmp/bareflank/build_gcc

export CFLAGS="-DNO_IMPLICIT_EXTERN_C=1"
export CXXFLAGS="-DNO_IMPLICIT_EXTERN_C=1"

../src_gcc/configure --target=x86_64-elf --prefix="$PREFIX" --disable-nls --enable-languages=c,c++ --without-headers --without-isl

make -j2 all-gcc
make -j2 install-gcc

popd
