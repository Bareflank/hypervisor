#!/bin/bash -e
#
# Copyright (C) 2019 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

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
