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

ASTYLE=./tools/astyle/astyle/build/gcc/bin/astyle

if [ $# -gt 0 ]; then
    if [ $1 = "clean" ]; then

        rm -Rf ./tools/astyle/astyle
        exit
    fi
fi

if [ ! -f $ASTYLE ]; then

	pushd ./tools/astyle/
	rm -Rf astyle

	tar xvf astyle.tar.gz
	cd astyle/build/gcc

	make -j

	popd
fi

find bfcrt/ -name "*.h" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find bfcrt/ -name "*.c" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find bfcrt/ -name "*.cpp" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;

find bfdrivers/ -name "*.h" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find bfdrivers/ -name "*.c" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find bfdrivers/ -name "*.cpp" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;

find bfelf_loader/ -name "*.h" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find bfelf_loader/ -name "*.c" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find bfelf_loader/ -name "*.cpp" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;

find bfm/ -name "*.h" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find bfm/ -name "*.c" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find bfm/ -name "*.cpp" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;

find bfunwind/ -name "*.h" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find bfunwind/ -name "*.c" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find bfunwind/ -name "*.cpp" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;

find bfvmm/ -name "*.h" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find bfvmm/ -name "*.c" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find bfvmm/ -name "*.cpp" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;

find common/ -name "*.h" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find common/ -name "*.c" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find common/ -name "*.cpp" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;

find include/ -name "*.h" ! -name 'hippomocks.h' -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find include/ -name "*.c" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find include/ -name "*.cpp" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;

if [[ -d extended_apis ]]; then
    find extended_apis/ -name "*.h" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
    find extended_apis/ -name "*.c" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
    find extended_apis/ -name "*.cpp" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
fi

if [[ -d hyperkernel ]]; then
    find hyperkernel/ -name "*.h" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
    find hyperkernel/ -name "*.c" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
    find hyperkernel/ -name "*.cpp" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
fi

if ls src_*/ 1> /dev/null 2>&1; then
    for d in $1/src_*/ ; do
        find $d -name "*.h" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
        find $d -name "*.c" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
        find $d -name "*.cpp" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
    done
fi

if ls hypervisor_*/ 1> /dev/null 2>&1; then
    for d in $1/hypervisor_*/ ; do
        find $d -name "*.h" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
        find $d -name "*.c" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
        find $d -name "*.cpp" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
    done
fi
