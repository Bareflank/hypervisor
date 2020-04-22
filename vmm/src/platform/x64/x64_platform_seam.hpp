#ifndef VMM_X64_PLATFORM_SEAM_HPP
#define VMM_X64_PLATFORM_SEAM_HPP

#include <vmm/platform/x64/x64_platform.hpp>

namespace vmm
{

template<
    class acpi_type,
    class loader_type
>
class x64_platform_seam :
    public x64_platform
{
public:

    // ---------------------------- acpi seam ----------------------------------
    uintptr_t acpi_rsdp_hpa_get() noexcept final
    { return m_acpi_type.acpi_rsdp_hpa_get(); }

    uintptr_t acpi_dmar_hpa_get() noexcept final
    { return m_acpi_type.acpi_dmar_hpa_get(); }

    // --------------------------- loader seam ---------------------------------
    uintptr_t loader_wakeup_entry_point_hpa_get() noexcept final
    { return m_loader_type.loader_wakeup_entry_point_hpa_get(); }

    bool loader_is_late_launch() noexcept final
    { return m_loader_type.loader_is_late_launch(); }

private:
    acpi_type m_acpi_type;
    loader_type m_loader_type;
};

}

#endif
