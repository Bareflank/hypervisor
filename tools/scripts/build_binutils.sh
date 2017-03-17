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

rm -Rf /tmp/bareflank/
mkdir -p /tmp/bareflank/

pushd /tmp/bareflank/

rm -Rf binutils-*.tar.gz
rm -Rf binutils-*/
rm -Rf src_binutils

wget -nv http://ftp.gnu.org/gnu/binutils/binutils-2.28.tar.gz && break

tar xfv binutils-*.tar.gz
mv binutils-*/ src_binutils
rm -Rf binutils-*.tar.gz

popd

rm -Rf /tmp/bareflank/build_binutils
mkdir -p /tmp/bareflank/build_binutils

pushd /tmp/bareflank/build_binutils

../src_binutils/configure --target=x86_64-elf --prefix="$HOME/usr/" --disable-nls --disable-werror --with-sysroot

make -j2
make -j2 install

popd
