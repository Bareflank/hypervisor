#ifndef VMMCTL_LINUX_VMM_INFO_HPP
#define VMMCTL_LINUX_VMM_INFO_HPP

#include <vmm_info.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/print.hpp>

namespace vmmctl
{

class linux_vmm_info :
    public vmm_info
{
public:

    linux_vmm_info() noexcept = default;

    bsl::exit_code
    dump() noexcept final
    {
        bsl::print("Dumping VMM debug output on Linux\n");
        //  TODO: Implement Me!
        return bsl::exit_failure;
    }

    bsl::exit_code
    status() noexcept final
    {
        bsl::print("Checking VMM status on Linux\n");
        //  TODO: Implement Me!
        return bsl::exit_failure;
    }
};

}

#endif
