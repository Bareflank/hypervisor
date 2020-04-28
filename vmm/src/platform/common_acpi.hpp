#ifndef VMM_PLATFORM_COMMON_ACPI_HPP
#define VMM_PLATFORM_COMMON_ACPI_HPP

#include <vmm/platform/acpi.hpp>

namespace vmm
{

class common_acpi:
    public acpi
{
public:

    uintptr_t get_acpi_rsdp_hpa() noexcept final
    {
        // TODO: Implement Me!
        return 0;
    }

    uintptr_t get_acpi_dmar_hpa() noexcept final
    {
        // TODO: Implement Me!
        return 0;
    }

    common_acpi() noexcept = default;
};

}

#endif
