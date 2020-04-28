#ifndef VMM_PLATFORM_COMMON_LOADER_HPP
#define VMM_PLATFORM_COMMON_LOADER_HPP

#include <vmm/platform/loader.hpp>

namespace vmm
{

class common_loader:
    public loader
{
public:

    uintptr_t get_loader_wakeup_entry_point_hpa() noexcept final
    {
        // TODO: Implement Me!
        return 0;
    }

    bool is_late_launch() noexcept final
    {
        // TODO: Implement Me!
        return false;
    }

    common_loader() noexcept = default;
};

}

#endif
