#ifndef VMMCTL_WINDOWS_VMM_LOADER_HPP
#define VMMCTL_WINDOWS_VMM_LOADER_HPP

#include <vmm_loader.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/print.hpp>

namespace vmmctl
{

class windows_vmm_loader :
    public vmm_loader
{
public:

    windows_vmm_loader() noexcept = default;

    bsl::exit_code
    load() noexcept final
    {
        bsl::print("Loading VMM on Windows\n");
        //  TODO: Implement Me!
        return bsl::exit_failure;
    }

    bsl::exit_code
    unload() noexcept final
    {
        bsl::print("Unloading VMM on Windows\n");
        //  TODO: Implement Me!
        return bsl::exit_failure;
    }

    bsl::exit_code
    start() noexcept final
    {
        bsl::print("Starting VMM on Windows\n");
        //  TODO: Implement Me!
        return bsl::exit_failure;
    }

    bsl::exit_code
    stop() noexcept final
    {
        bsl::print("Stopping VMM on Windows\n");
        //  TODO: Implement Me!
        return bsl::exit_failure;
    }
};

}

#endif
