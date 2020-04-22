#ifndef VMM_PLATFORM_COMMON_ACPI_HPP
#define VMM_PLATFORM_COMMON_ACPI_HPP

#include <vmm/platform/acpi.hpp>

namespace vmm
{

class common_acpi:
    public acpi
{
public:

    uintptr_t acpi_rsdp_hpa_get() noexcept final
    {
        // TODO: Implement Me!
        return 0;
    }

    uintptr_t acpi_dmar_hpa_get() noexcept final
    {
        // TODO: Implement Me!
        return 0;
    }

    common_acpi() noexcept = default;
};

}

#endif
