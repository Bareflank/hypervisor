check_status()
{
    if [ $? -ne 0 ] ; then
        echo BFTest FAILED > /dev/ttyS1
        sleep 31
    fi
}

test_hypervisor()
{
    sudo make > /dev/ttyS1 ; check_status
    sudo make test > /dev/ttyS1 ; check_status
    sudo ./tools/tests/test_hypervisor.sh > /dev/ttyS1 ; check_status
    echo Hypervisor Done > /dev/ttyS1
}

test_extended_apis()
{
    git clone https://github.com/Bareflank/extended_apis > /dev/ttyS1 ; check_status
    sudo ./configure -m extended_apis/bin/extended_apis.modules > /dev/ttyS1 ; check_status
    sudo make > /dev/ttyS1 ; check_status
    sudo make test > /dev/ttyS1 ; check_status
    sudo ./extended_apis/tests/test_extended_apis.sh > /dev/ttyS1 ; check_status
    echo EAPIs Done > /dev/ttyS1
}

test_hyperkernel()
{
    git clone https://github.com/Bareflank/hyperkernel > /dev/ttyS1 ; check_status
    sudo ./configure -m hyperkernel/bin/hyperkernel.modules > /dev/ttyS1 ; check_status
    sudo make > /dev/ttyS1 ; check_status
    sudo make test > /dev/ttyS1 ; check_status
    sudo ./hyperkernel/tests/test_hyperkernel.sh > /dev/ttyS1 ; check_status
    echo Hyperkernel Done > /dev/ttyS1
}

test_vpid()
{
    git clone https://github.com/Bareflank/hypervisor_example_vpid > /dev/ttyS1 ; check_status
    sudo ./configure -m hypervisor_example_vpid/bin/vpid.modules -e hypervisor_example_vpid >/dev/ttyS1 ; check_status
    sudo make > /dev/ttyS1 ; check_status
    sudo make driver_load > /dev/ttyS1 ; check_status
    sudo make quick > /dev/ttyS1 ; check_status
    sudo make status > /dev/ttyS1 ; check_status
    sudo make dump > /dev/ttyS1 ; check_status
    sudo make stop > /dev/ttyS1 ; check_status
    sudo make driver_unload > /dev/ttyS1 ; check_status
    echo VPID Done > /dev/ttyS1
}

test_cpuid()
{
    git clone https://github.com/Bareflank/hypervisor_example_cpuidcount > /dev/ttyS1 ; check_status
    sudo ./configure -m hypervisor_example_cpuidcount/bin/cpuidcount.modules > /dev/ttyS1 ; check_status
    sudo make > /dev/ttyS1 ; check_status
    sudo make driver_load > /dev/ttyS1 ; check_status
    sudo make quick > /dev/ttyS1 ; check_status
    sudo ARGS="string json '{\"get\":\"count\"}'" make vmcall > /dev/ttyS1 ; check_status
    sudo make stop > /dev/ttyS1 ; check_status
    sudo make driver_unload > /dev/ttyS1 ; check_status
    echo CPUID Done > /dev/ttyS1
}

test_hook()
{
    git clone https://github.com/Bareflank/extended_apis_example_hook src_extended_apis_example_hook > /dev/ttyS1 ; check_status
    sudo ./configure -m src_extended_apis_example_hook/bin/hook.modules > /dev/ttyS1 ; check_status
    sudo make >/dev/ttyS1 ; check_status
    sudo make driver_load > /dev/ttyS1 ; check_status
    sudo make quick > /dev/ttyS1 ; check_status
    sudo ./makefiles/src_extended_apis_example_hook/app/bin/native/hook > /dev/ttyS1 ; check_status
    sudo make stop > /dev/ttyS1 ; check_status
    sudo make driver_unload > /dev/ttyS1 ; check_status
    echo Hook Done > /dev/ttyS1 
}

cd hypervisor
git pull > /dev/ttyS1 ; check_status
sudo ./tools/scripts/setup_ubuntu.sh --compiler clang_38 >/dev/ttyS ; check_status

# Tests
test_hypervisor
test_extended_apis
test_hyperkernel
test_vpid
test_cpuid
test_hook

echo BFTest SUCCESS > /dev/ttyS1
