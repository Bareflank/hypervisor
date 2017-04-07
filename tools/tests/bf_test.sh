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
    echo "BFTest EXIT"
}



test_hypervisor()
{
    sudo make
    if [ "$distro" != "Cygwin" ] ; then
        sudo make test
    fi
    sudo ./tools/tests/test_hypervisor.sh
    echo Hypervisor Done
}



test_extended_apis()
{
    n=0
    until [ $n -ge 3 ]
    do
        git clone https://github.com/Bareflank/extended_apis && break
        n=$[$n+1]
        sleep 15
    done

    if [ "$distro" != "Cygwin" ] ; then
        sudo ./configure -m extended_apis/bin/extended_apis.modules
        sudo make
        sudo make test
        sudo ./extended_apis/tests/test_extended_apis.sh
    else
        sudo ./configure -m extended_apis/bin/extended_apis.modules --compiler clang --linker $HOME/usr/bin/x86_64-elf-ld.exe
        sudo make
    fi
    echo EAPIs Done
}



test_hyperkernel()
{
    n=0
    until [ $n -ge 3 ]
    do
        git clone https://github.com/Bareflank/hyperkernel && break
        n=$[$n+1]
        sleep 15
    done

    if [ "$distro" != "Cygwin" ] ; then
        sudo ./configure -m hyperkernel/bin/hyperkernel.modules
        sudo make
        sudo make test
    else
        sudo ./configure -m hyperkernel/bin/hyperkernel.modules --compiler clang --linker $HOME/usr/bin/x86_64-elf-ld.exe
        sudo make
    fi
    sudo ./hyperkernel/tests/test_hyperkernel.sh
    echo Hyperkernel Done
}



test_vpid()
{
    n=0
    until [ $n -ge 3 ]
    do
        git clone https://github.com/Bareflank/hypervisor_example_vpid && break
        n=$[$n+1]
        sleep 15
    done

    if [ "$distro" != "Cygwin" ] ; then
        sudo ./configure -m hypervisor_example_vpid/bin/vpid.modules -e hypervisor_example_vpid
    else
        sudo ./configure -m hypervisor_example_vpid/bin/vpid.modules -e hypervisor_example_vpid --compiler clang --linker $HOME/usr/bin/x86_64-elf-ld.exe
    fi
    sudo make
    sudo make driver_load
    sudo make quick
    sudo make status
    sudo make dump
    sudo make stop
    sudo make driver_unload
    echo VPID Done
}



test_cpuid()
{
    n=0
    until [ $n -ge 3 ]
    do
        git clone https://github.com/Bareflank/hypervisor_example_cpuidcount && break
        n=$[$n+1]
        sleep 15
    done

    if [ "$distro" != "Cygwin" ] ; then
        sudo ./configure -m hypervisor_example_cpuidcount/bin/cpuidcount.modules
    else
        sudo ./configure -m hypervisor_example_cpuidcount/bin/cpuidcount.modules --compiler clang --linker $HOME/usr/bin/x86_64-elf-ld.exe
    fi
    sudo make
    sudo make driver_load
    sudo make quick
    sudo ARGS="string json '{\"get\":\"count\"}'" make vmcall
    sudo make stop
    sudo make driver_unload
    echo CPUID Done
}



test_hook()
{
    n=0
    until [ $n -ge 3 ]
    do
        git clone https://github.com/Bareflank/extended_apis_example_hook src_extended_apis_example_hook && break
        n=$[$n+1]
        sleep 15
    done

    if [ "$distro" != "Cygwin" ] ; then
        sudo ./configure -m src_extended_apis_example_hook/bin/hook.modules
    else
        sudo ./configure -m src_extended_apis_example_hook/bin/hook.modules --compiler clang --linker $HOME/usr/bin/x86_64-elf-ld.exe
    fi
    sudo make
    sudo make driver_load
    sudo make quick
    sudo ./makefiles/src_extended_apis_example_hook/app/bin/native/hook
    sudo make stop
    sudo make driver_unload
    echo Hook Done
}



trap report_error EXIT
distro=$(uname -o)
# Tests assume you are in the hypervisor directory and have run your setup_XXX script
test_hypervisor
test_extended_apis
test_hyperkernel
test_vpid
test_cpuid
test_hook

echo BFTest SUCCESS
sleep 60;
