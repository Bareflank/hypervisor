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

# ------------------------------------------------------------------------------
# Colors
# ------------------------------------------------------------------------------

CB='\033[1;35m'
CC='\033[1;36m'
CG='\033[1;32m'
CE='\033[0m'

export INCLUDE_LIBCXX_UNITTESTS=yes

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

loop_start_stop() {
    echo -e "$CC""testing:$CB loop_start_stop$CE"
    make driver_load > /dev/null 2>&1
    make loop NUM=100
    make driver_unload > /dev/null 2>&1
}

stress_test() {
    echo -e "$CC""testing:$CB stress_test$CE"
    make driver_load > /dev/null 2>&1
    make quick
    make clean
    make
    make test
    make stop
    make driver_unload > /dev/null 2>&1
}

turn_off_tests() {
    echo -e "$CC""testing:$CB turn_off_tests$CE"
    make driver_load > /dev/null 2>&1
    make quick
    make quick
    make quick
    make driver_unload > /dev/null 2>&1
}

vmcall_version() {
    echo -e "$CC""testing:$CB vmcall_version$CE"
    make driver_load > /dev/null 2>&1
    make quick
    ARGS="versions 0" make vmcall
    ARGS="versions 1" make vmcall
    ARGS="versions 10" make vmcall
    ARGS="versions 100" make vmcall || true
    make driver_unload > /dev/null 2>&1
}

vmcall_registers() {
    echo -e "$CC""testing:$CB vmcall_registers$CE"
    make driver_load > /dev/null 2>&1
    make quick
    ARGS="registers 1" make vmcall
    ARGS="registers 1 2 3 4 5 6 7 8 9 10 11" make vmcall
    ARGS="registers 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16" make vmcall
    make driver_unload > /dev/null 2>&1
}

vmcall_event() {
    echo -e "$CC""testing:$CB vmcall_event$CE"
    make driver_load > /dev/null 2>&1
    make quick
    ARGS="event 1" make vmcall
    ARGS="event 2" make vmcall
    make driver_unload > /dev/null 2>&1
}

vmcall_unittest() {
    echo -e "$CC""testing:$CB vmcall_unittest$CE"
    make driver_load > /dev/null 2>&1
    make quick
    echo -e ""
    ARGS="unittest 0x1001" make vmcall
    ARGS="unittest 0x1002" make vmcall
    ARGS="unittest 0x1003" make vmcall
    ARGS="unittest 0x1004" make vmcall
    ARGS="unittest 0x1005" make vmcall
    ARGS="unittest 0x1006" make vmcall
    ARGS="unittest 0x1007" make vmcall
    ARGS="unittest 0x1008" make vmcall
    ARGS="unittest 0x1009" make vmcall
    ARGS="unittest 0x100A" make vmcall
    ARGS="unittest 0x1100" make vmcall
    ARGS="unittest 0x1101" make vmcall
    echo -e ""
    make driver_unload > /dev/null 2>&1
}

vmcall_string_unformatted() {
    echo -e "$CC""testing:$CB vmcall_string_unformatted$CE"
    make driver_load > /dev/null 2>&1
    make quick
    ARGS="string unformatted 'hello world'" make vmcall
    ARGS="string unformatted 'hello world'" make vmcall
    ARGS="string unformatted 'hello world'" make vmcall
    ARGS="string unformatted 'hello world'" make vmcall
    ARGS="string unformatted 'hello world'" make vmcall
    make driver_unload > /dev/null 2>&1
}

vmcall_string_json() {
    echo -e "$CC""testing:$CB vmcall_string_json$CE"
    make driver_load > /dev/null 2>&1
    make quick
    ARGS="string json '{\"msg\":\"hello world\"}'" make vmcall
    ARGS="string json '{\"msg\":\"hello world\"}'" make vmcall
    ARGS="string json '{\"msg\":\"hello world\"}'" make vmcall
    ARGS="string json '{\"msg\":\"hello world\"}'" make vmcall
    ARGS="string json '{\"msg\":\"hello world\"}'" make vmcall
    ARGS="string json 'hello world'" make vmcall || true
    make driver_unload > /dev/null 2>&1
}

vmcall_data_unformatted() {
    echo -e "$CC""testing:$CB vmcall_data_unformatted$CE"
    make driver_load > /dev/null 2>&1
    make quick
    rm -Rf /tmp/test_indata.txt
    rm -Rf /tmp/test_outdata.txt
    echo "hello world" > /tmp/test_indata.txt
    ARGS="data unformatted /tmp/test_indata.txt /tmp/test_outdata.txt" make vmcall
    if cmp -s "/tmp/test_indata.txt" "/tmp/test_outdata.txt"; then
        rm -Rf /tmp/test_indata.txt
        rm -Rf /tmp/test_outdata.txt
    else
        echo "ERROR: binary files do not match"
        exit 1
    fi
    make driver_unload > /dev/null 2>&1
}

# ------------------------------------------------------------------------------
# Run Tests
# ------------------------------------------------------------------------------

loop_start_stop
stress_test
turn_off_tests
vmcall_version
vmcall_registers
vmcall_event
vmcall_unittest
vmcall_string_unformatted
vmcall_string_json
vmcall_data_unformatted

# ------------------------------------------------------------------------------
# Done
# ------------------------------------------------------------------------------

echo -e ""
echo -e "$CC""completed:$CG Success$CE"
echo -e ""
