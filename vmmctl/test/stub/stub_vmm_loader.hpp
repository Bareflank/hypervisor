#ifndef VMMCTL_STUB_VMM_LOADER_HPP
#define VMMCTL_STUB_VMM_LOADER_HPP

#include <vmm_loader.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/print.hpp>

namespace vmmctl
{

class stub_vmm_loader :
    public vmm_loader
{
public:

    stub_vmm_loader() noexcept = default;

    bsl::exit_code
    load() noexcept final
    {
        bsl::print("TEST STUB: Loading VMM\n");
        return bsl::exit_success;
    }

    bsl::exit_code
    unload() noexcept final
    {
        bsl::print("TEST STUB: Unloading VMM\n");
        return bsl::exit_success;
    }

    bsl::exit_code
    start() noexcept final
    {
        bsl::print("TEST STUB: Starting VMM\n");
        return bsl::exit_success;
    }

    bsl::exit_code
    stop() noexcept final
    {
        bsl::print("TEST STUB: Stopping VMM\n");
        return bsl::exit_success;
    }
};

}

#endif


