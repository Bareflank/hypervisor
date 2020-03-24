#ifndef VMMCTL_UNSUPPORTED_VMM_LOADER_HPP
#define VMMCTL_UNSUPPORTED_VMM_LOADER_HPP

#include <vmm_loader.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/print.hpp>

namespace vmmctl
{

class unsupported_vmm_loader :
    public vmm_loader
{
public:

    unsupported_vmm_loader() noexcept = default;

    bsl::exit_code
    load() noexcept final
    {
        bsl::print("Loading a VMM is unsupported on the current platform\n");
        return bsl::exit_failure;
    }

    bsl::exit_code
    unload() noexcept final
    {
        bsl::print("Unloading a VMM is unsupported on the current platform\n");
        return bsl::exit_failure;
    }

    bsl::exit_code
    start() noexcept final
    {
        bsl::print("Starting a VMM is unsupported on the current platform\n");
        return bsl::exit_failure;
    }

    bsl::exit_code
    stop() noexcept final
    {
        bsl::print("Stopping a VMM is unsupported on the current platform\n");
        return bsl::exit_failure;
    }
};

}

#endif



