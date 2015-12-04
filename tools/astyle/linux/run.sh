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

ASTYLE=./tools/astyle/linux/astyle/build/gcc/bin/astyle

if [ $# -gt 0 ]; then
    if [ $1 = "clean" ]; then

        rm -Rf ./tools/astyle/linux/astyle
        exit
    fi
fi

if [ ! -f $ASTYLE ]; then

	pushd ./tools/astyle/linux/
	rm -Rf astyle

	tar xvf astyle_2.05.1_linux.tar.gz
	cd astyle/build/gcc

	make -j

	popd
fi

find bfelf_loader/ -name "*.h" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find bfelf_loader/ -name "*.c" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find bfelf_loader/ -name "*.cpp" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;

find bfm/ -name "*.h" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find bfm/ -name "*.c" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find bfm/ -name "*.cpp" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;

find bfvmm/ -name "*.h" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find bfvmm/ -name "*.c" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find bfvmm/ -name "*.cpp" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;

find common/ -name "*.h" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find common/ -name "*.c" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find common/ -name "*.cpp" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;

find driver_entry/ -name "*.h" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find driver_entry/ -name "*.c" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find driver_entry/ -name "*.cpp" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;

find include/ -name "*.h" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find include/ -name "*.c" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find include/ -name "*.cpp" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
