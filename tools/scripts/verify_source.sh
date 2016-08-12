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

# Note:
#
# This is just a development tool and is not a supported script. If you do
# want to use this, it's only been tested on Ubuntu 16.04 with
# clang-tidy-3.8 installed.
#
# Also note that at a minimum, this shows which clang-tidy analysis options
# have been run against the code.
#
# Ignore:
#
# - CastToStruct: we disable this at the moment because we are doing a lot
#   of legit casting in the ELF loader, as this is really how the spec is
#   written.
#
# - UnreachableCode: we disable this because it seems to output buggy
#   results. Furthermore, its not really needed since Coveralls tells us
#   if code cannot be reached, which is also evidence this check is not
#   working right, as it has a lot of false positives.
#
# - VirtualCall: this does't work with hippomocks as a lot of functions are
#   labled virtual so that they can be mocked, which causes this to create
#   false positives.
#
# - reinterpret-cast: There are legit cases where we need reinterpret_cast.
#   As a result, we have disabled this. That being said, each instance were
#   it is used has been reviewed, and determined to be needed. The remaining
#   instances were removed in place of safer code.
#
# - braces-around-statements: We use this a lot
#

run-clang-tidy-3.8.py -checks=clan*,-clang-analyzer-alpha.core.CastToStruct,-clang-analyzer-alpha.deadcode.UnreachableCode,-clang-analyzer-alpha.cplusplus.VirtualCall $PWD
run-clang-tidy-3.8.py -checks=cert*,-clang-analyzer* $PWD
run-clang-tidy-3.8.py -checks=misc*,-clang-analyzer* $PWD
run-clang-tidy-3.8.py -checks=perf*,-clang-analyzer* $PWD
run-clang-tidy-3.8.py -checks=cppc*,-clang-analyzer*,-cppcoreguidelines-pro-type-reinterpret-cast $PWD
run-clang-tidy-3.8.py -checks=read*,-clang-analyzer*,-readability-braces-around-statements $PWD
run-clang-tidy-3.8.py -checks=mode*,-clang-analyzer* $PWD
