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

pushd /tmp/bareflank/

rm -Rf source_llvm

if [[ -z "$CUSTOM_LLVM_BRANCH" ]]; then
    llvm_branch=$LLVM_RELEASE
else
    llvm_branch=$CUSTOM_LLVM_BRANCH
fi

if [[ -z "$CUSTOM_LLVM_URL" ]]; then
    llvm_url="http://llvm.org/git/llvm"
else
    llvm_url=$CUSTOM_LLVM_URL
fi

if [[ -z "$CUSTOM_CLANG_BRANCH" ]]; then
    clang_branch=$LLVM_RELEASE
else
    clang_branch=$CUSTOM_CLANG_BRANCH
fi

if [[ -z "$CUSTOM_CLANG_URL" ]]; then
    clang_url="http://llvm.org/git/clang.git"
else
    clang_url=$CUSTOM_CLANG_URL
fi

n=0
until [ $n -ge 5 ]
do
    git clone --depth 1 -b $llvm_branch $llvm_url source_llvm && break
    n=$[$n+1]
    sleep 15
done

cd source_llvm/tools

n=0
until [ $n -ge 5 ]
do
    git clone --depth 1 -b $clang_branch $clang_url && break
    n=$[$n+1]
    sleep 15
done

popd
