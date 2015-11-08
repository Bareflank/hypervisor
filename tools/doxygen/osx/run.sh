#!/bin/bash

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

set -e

if [ $# -gt 0 ]; then
    if [ $1 = "clean" ]; then

        rm -Rf ./tools/doxygen/osx/src
        exit
    fi
fi

if [ ! -f tools/doxygen/osx/src/build/bin/doxygen ]; then

	pushd tools/doxygen/osx
	rm -Rf src

	git clone https://github.com/doxygen/doxygen.git src

	cd src
	mkdir build
  	cd build
  	cmake -G "Unix Makefiles" ../
	make -j

	popd
fi

mkdir -p doc

cd doc
../tools/doxygen/osx/src/build/bin/doxygen ../tools/doxygen/config.txt
