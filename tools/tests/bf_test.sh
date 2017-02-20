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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

set -e
report_error()
{
    echo "BFTest EXIT" > /dev/ttyS1
}

test_hypervisor()
{
    sudo make > /dev/ttyS1
    sudo make test > /dev/ttyS1
    sudo ./tools/tests/test_hypervisor.sh > /dev/ttyS1
    echo Hypervisor Done > /dev/ttyS1
}

test_extended_apis()
{
    git clone https://github.com/Bareflank/extended_apis > /dev/ttyS1
    sudo ./configure -m extended_apis/bin/extended_apis.modules > /dev/ttyS1
    sudo make > /dev/ttyS1
    sudo make test > /dev/ttyS1
    sudo ./extended_apis/tests/test_extended_apis.sh > /dev/ttyS1
    echo EAPIs Done > /dev/ttyS1
}

test_hyperkernel()
{
    git clone https://github.com/Bareflank/hyperkernel > /dev/ttyS1
    sudo ./configure -m hyperkernel/bin/hyperkernel.modules > /dev/ttyS1
    sudo make > /dev/ttyS1
    sudo make test > /dev/ttyS1
    sudo ./hyperkernel/tests/test_hyperkernel.sh > /dev/ttyS1
    echo Hyperkernel Done > /dev/ttyS1
}

test_vpid()
{
    git clone https://github.com/Bareflank/hypervisor_example_vpid > /dev/ttyS1
    sudo ./configure -m hypervisor_example_vpid/bin/vpid.modules -e hypervisor_example_vpid >/dev/ttyS1
    sudo make > /dev/ttyS1
    sudo make driver_load > /dev/ttyS1
    sudo make quick > /dev/ttyS1
    sudo make status > /dev/ttyS1
    sudo make dump > /dev/ttyS1
    sudo make stop > /dev/ttyS1
    sudo make driver_unload > /dev/ttyS1
    echo VPID Done > /dev/ttyS1
}

test_cpuid()
{
    git clone https://github.com/Bareflank/hypervisor_example_cpuidcount > /dev/ttyS1
    sudo ./configure -m hypervisor_example_cpuidcount/bin/cpuidcount.modules > /dev/ttyS1
    sudo make > /dev/ttyS1
    sudo make driver_load > /dev/ttyS1
    sudo make quick > /dev/ttyS1
    sudo ARGS="string json '{\"get\":\"count\"}'" make vmcall > /dev/ttyS1
    sudo make stop > /dev/ttyS1
    sudo make driver_unload > /dev/ttyS1
    echo CPUID Done > /dev/ttyS1
}

test_hook()
{
    git clone https://github.com/Bareflank/extended_apis_example_hook src_extended_apis_example_hook > /dev/ttyS1
    sudo ./configure -m src_extended_apis_example_hook/bin/hook.modules > /dev/ttyS1
    sudo make >/dev/ttyS1
    sudo make driver_load > /dev/ttyS1
    sudo make quick > /dev/ttyS1
    sudo ./makefiles/src_extended_apis_example_hook/app/bin/native/hook > /dev/ttyS1
    sudo make stop > /dev/ttyS1
    sudo make driver_unload > /dev/ttyS1
    echo Hook Done > /dev/ttyS1
}

trap report_error EXIT
# Tests assume you are in the ~/hypervisor directory and have run your setup_XXX script
test_hypervisor
test_extended_apis
test_hyperkernel
test_vpid
test_cpuid
test_hook

echo BFTest SUCCESS > /dev/ttyS1
sleep 60;
