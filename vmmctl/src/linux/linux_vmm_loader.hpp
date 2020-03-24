#ifndef VMMCTL_LINUX_VMM_LOADER_HPP
#define VMMCTL_LINUX_VMM_LOADER_HPP

#include <vmm_loader.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/print.hpp>

namespace vmmctl
{

class linux_vmm_loader :
    public vmm_loader
{
public:

    linux_vmm_loader() noexcept = default;

    bsl::exit_code
    load() noexcept final
    {
        bsl::print("Loading VMM on Linux\n");
        //  TODO: Implement Me!
        return bsl::exit_failure;
    }

    bsl::exit_code
    unload() noexcept final
    {
        bsl::print("Unloading VMM on Linux\n");
        //  TODO: Implement Me!
        return bsl::exit_failure;
    }

    bsl::exit_code
    start() noexcept final
    {
        bsl::print("Starting VMM on Linux\n");
        //  TODO: Implement Me!
        return bsl::exit_failure;
    }

    bsl::exit_code
    stop() noexcept final
    {
        bsl::print("Stopping VMM on Linux\n");
        //  TODO: Implement Me!
        return bsl::exit_failure;
    }
};

}

#endif


