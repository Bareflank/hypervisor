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

%ENV_SOURCE%

pushd $BUILD_ABS

if [[ -z "$CUSTOM_LIBCXXABI_BRANCH" ]]; then
    branch=$LLVM_RELEASE
else
    branch=$CUSTOM_LIBCXXABI_BRANCH
fi

if [[ -z "$CUSTOM_LIBCXXABI_URL" ]]; then
    url="http://llvm.org/git/libcxxabi"
else
    url=$CUSTOM_LIBCXXABI_URL
fi

n=0
until [ $n -ge 5 ]
do
    git clone --depth 1 -b $branch $url source_libcxxabi && break
    n=$[$n+1]
    sleep 15
done

cd source_libcxxabi
patch -p1 < $HYPER_ABS/tools/patches/libcxxabi.patch

popd
