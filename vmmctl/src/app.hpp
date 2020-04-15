#ifndef VMMCTL_VMMCTL_APPLICATION_HPP
#define VMMCTL_VMMCTL_APPLICATION_HPP

#include <vmm_info.hpp>
#include <vmm_loader.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/print.hpp>
// #include <bsl/is_base_of.hpp>

namespace vmmctl
{

template<
    class vmm_info_type,
    class vmm_loader_type
>
class app final
{
public:

    static bsl::exit_code
    run() noexcept 
    {
        // static_assert(bsl::is_base_of<vmmctl::vmm_info, vmm_info_type>::value,
        //               "vmm_info_type must conform to vmmctl::vmm_info interface");
        // static_assert(bsl::is_base_of<vmmctl::vmm_loader, vmm_loader_type>::value,
        //               "vmm_loader_type must conform to vmmctl::vmm_loader interface");

        bsl::print("Running vmmctl app\n");

        vmm_info_type info{};
        vmm_loader_type loader{};

        loader.load();
        loader.start();
        loader.stop();
        loader.unload();

        info.dump();
        info.status();

        return bsl::exit_success;
    }
};

}

#endif

