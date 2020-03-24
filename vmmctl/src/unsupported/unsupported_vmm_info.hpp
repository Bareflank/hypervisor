#ifndef VMMCTL_UNSUPPORTED_VMM_INFO_HPP
#define VMMCTL_UNSUPPORTED_VMM_INFO_HPP

#include <vmm_info.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/print.hpp>

namespace vmmctl
{

class unsupported_vmm_info :
    public vmm_info
{
public:

    unsupported_vmm_info() noexcept = default;

    bsl::exit_code
    dump() noexcept final
    {
        bsl::print("Dumping VMM debug output is unsupported on the current platform\n");
        return bsl::exit_failure;
    }

    bsl::exit_code
    status() noexcept final
    {
        bsl::print("Checking VMM status is unsupported on the current platform\n");
        return bsl::exit_failure;
    }
};

}

#endif
