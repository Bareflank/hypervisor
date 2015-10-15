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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

set -e

ASTYLE=./tools/astyle/osx/astyle/build/mac/bin/astyle

if [ $# -gt 0 ]; then
    if [ $1 = "clean" ]; then

        rm -Rf ./tools/astyle/osx/astyle
        exit
    fi
fi

if [ ! -f $ASTYLE ]; then

	pushd ./tools/astyle/osx/
	rm -Rf astyle

	tar xvf astyle_2.05.1_macosx.tar.gz
	cd astyle/build/mac

	make -j

	popd
fi

find src/ -name "*.h" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find src/ -name "*.c" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find src/ -name "*.cpp" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;

find test/ -name "*.h" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find test/ -name "*.c" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
find test/ -name "*.cpp" -exec $ASTYLE --options=./tools/astyle/astyle.config {} \;
