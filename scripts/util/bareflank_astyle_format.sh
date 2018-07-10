#!/bin/bash -e
#
# Bareflank Hypervisor
# Copyright (C) 2015 Assured Information Security, Inc.
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

get_changed_files() {
    if [[ "$1" == "all" ]]; then
        files=$(git ls-files | grep -Ee "\.(cpp|h|c)$" || true)
    elif [[ "$1" == "upstream" ]]; then
        files=$(git diff --relative --name-only --diff-filter=d upstream/master $PWD | grep -Ee "\.(cpp|h|c)$" || true)
    else
        files=$(git diff --relative --name-only --diff-filter=d origin $PWD | grep -Ee "\.(cpp|h|c)$" || true)
    fi
}

if [[ "$#" -lt 2 ]]; then
    echo "ERROR: missing arguments"
    exit 1
fi

if [[ ! "$2" == "all" ]] && [[ ! "$2" == "diff" ]] && [[ ! "$2" == "upstream" ]]; then
    echo "ERROR: invalid opcode '$2'. Expecting 'all', 'diff' or 'upstream'"
    exit 1
fi

cd $3
get_changed_files $2

if [[ -z "$files" ]]; then
    echo -e "\033[1;32m\xE2\x9C\x93 nothing changed:\033[0m $3";
    exit 0
fi

$1 \
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
    $files > $OUTPUT

if [[ -z $(grep -s Formatted $OUTPUT) ]]; then
    echo -e "\033[1;32m\xE2\x9C\x93 passed:\033[0m $3";
else
    echo -e ""
    echo -e "\033[1;31m########################\033[0m"
    echo -e "\033[1;31m# Astyle Checks Failed #\033[0m"
    echo -e "\033[1;31m########################\033[0m"
    echo -e ""
    grep --color -s Formatted $OUTPUT | awk '{print $2}'
    echo ""
    exit -1
fi

rm $OUTPUT
