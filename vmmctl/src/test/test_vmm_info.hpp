#ifndef VMMCTL_TEST_VMM_INFO_HPP
#define VMMCTL_TEST_VMM_INFO_HPP

#include <vmm_info.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/print.hpp>

namespace vmmctl
{

class test_vmm_info :
    public vmm_info
{
public:

    test_vmm_info() noexcept = default;

    bsl::exit_code
    dump() noexcept final
    {
        bsl::print("TEST STUB: Dumping VMM debug output\n");
        return bsl::exit_success;
    }

    bsl::exit_code
    status() noexcept final
    {
        bsl::print("TEST STUB: Checking VMM status\n");
        return bsl::exit_success;
    }
};

}

#endif
