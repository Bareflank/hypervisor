#!/bin/sh -e
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

if [[ ! $PATH == *"bfprefix"* ]]; then

    BAREFLANK_SOURCE_DIR="$(cd $(dirname ${BASH_SOURCE[0]}) && pwd)"

    if [[ -z "$1" ]]; then
        BAREFLANK_BINARY_DIR="$BAREFLANK_SOURCE_DIR/build"
    else
        BAREFLANK_BINARY_DIR="$1"
    fi

    if [[ ! -d $BAREFLANK_BINARY_DIR ]]; then
        >&2 echo "$BAREFLANK_BINARY_DIR does not exist, creating it"
        mkdir -p $BAREFLANK_BINARY_DIR
    fi

    export CTEST_OUTPUT_ON_FAILURE=yes
    export PATH="$BAREFLANK_BINARY_DIR/bfprefix/bin:$PATH"

    alias s='cd $BAREFLANK_SOURCE_DIR'
    alias b='cd $BAREFLANK_BINARY_DIR'

else
    >&2 echo "bareflank environment already sourced"
fi
