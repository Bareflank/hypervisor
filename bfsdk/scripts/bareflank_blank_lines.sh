#!/bin/bash -e
#
# Bareflank Hypervisor
# Copyright (C) 2017 Assured Information Security, Inc.
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

OUTPUT=$PWD/.remove_blank_scratch

ls_not_deleted() {
    git ls-files | sort | comm -23 - <( git ls-files -d | sort )
}

rm -f $OUTPUT

if [[ "$#" -lt 1 ]]; then
    echo "ERROR: missing arguments"
    exit 1
fi

if [[ "$#" == 2 ]]; then
    echo $2
    cd $2
fi

if [[ ! "$1" == "all" ]] && [[ ! "$1" == "diff" ]]; then
    echo "ERROR: invalid opcode '$1'. Expecting 'all' or 'diff'"
    exit 1
fi

if [[ "$1" == "all" ]]; then
    files=$(ls_not_deleted | grep -Ee "\.(cpp|h|c)$" || true)
else
    files=$(git diff --relative --name-only --diff-filter=d HEAD $PWD | grep -Ee "\.(cpp|h|c)$" || true)

    echo "Files undergoing blank line checks:"
    for f in $files; do
        echo "  - $f"
    done
fi

if [[ -z "${files// }" ]]; then
    echo -e "\033[1;32m\xe2\x9c\x93 no files to format. blank line check passed\033[0m"
    exit 0
fi

REMOVE_BLANKS='
    /^[ \t]*$/ {
        if (consecutive_blanks) {
            extra_blanks++
        } else {
            print $0
        }
        consecutive_blanks++
    }

    /[^ \t]/ {
        consecutive_blanks = 0;
        print $0
    }

    END {
        exit (extra_blanks > 0)
    }
'

check_files() {
    for file in $files; do
        if ! awk "$REMOVE_BLANKS" < "$file" > "$OUTPUT"; then
            echo "$file"
            cat "$OUTPUT" > "$file"
        fi
    done
}

modified="$(check_files)"

if [[ -z "$modified" ]]; then
    echo -e "\033[1;32m\xe2\x9c\x93 blank line check passed\033[0m"
    rm -f "$OUTPUT"
else
    echo -e "\xe2\x9c\x97 blank line check failed: the following files were formatted:"
    echo "$modified"
    rm -f "$OUTPUT"
    exit -1
fi
