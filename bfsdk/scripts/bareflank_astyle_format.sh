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

OUTPUT=$PWD/.astyle_results.txt

rm -f $OUTPUT

if [[ "$#" -lt 1 ]]; then
    echo "ERROR: missing arguments"
    exit 1
fi

if [[ "$#" == 2 ]]; then
    cd $2
fi

if [[ ! "$1" == "all" ]] && [[ ! "$1" == "diff" ]]; then
    echo "ERROR: invalid opcode '$1'. Expecting 'all' or 'diff'"
    exit 1
fi

if [[ "$1" == "all" ]]; then
    FILES=$(git ls-files | grep -Ee "\.(cpp|h|c)$" | awk -v dir="$PWD/" '{print dir $0}' || true)
else
    FILES=$(git diff --name-only --diff-filter=ACM HEAD | grep -Ee "\.(cpp|h|c)$" | awk -v dir="$PWD/" '{print dir $0}' || true)
fi

if [[ -z "${FILES// }" ]]; then
    echo -e "\033[1;32m\xe2\x9c\x93 no files to format. astyle passed\033[0m"
    exit 0
fi

if [[ ! -x "$(which astyle)" ]]; then
   echo "ERROR: astyle not found in PATH"
   exit 1
fi

astyle \
    --style=1tbs \
    --lineend=linux \
    --suffix=none \
    --pad-oper \
    --unpad-paren \
    --break-closing-brackets \
    --align-pointer=name \
    --align-reference=name \
    --indent-preproc-define \
    --indent-switches \
    --indent-col1-comments \
    --keep-one-line-statements \
    --keep-one-line-blocks \
    --pad-header \
    --convert-tabs \
    --min-conditional-indent=0 \
    --indent=spaces=4 \
    --close-templates \
    --add-brackets \
    --break-after-logical \
    $FILES > $OUTPUT

if [[ -z $(grep -s Formatted $OUTPUT) ]]; then
    echo -e "\033[1;32m\xe2\x9c\x93 astyle passed\033[0m"
    rm -Rf $OUTPUT
    exit
else
    echo -e "\xe2\x9c\x97 astyle failed: the following files were formatted:"
    grep -s Formatted $OUTPUT | awk '{print $2}'
    echo ""
    rm -Rf $OUTPUT
    exit -1
fi
