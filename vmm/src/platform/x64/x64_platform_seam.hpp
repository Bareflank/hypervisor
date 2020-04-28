#ifndef VMM_X64_PLATFORM_SEAM_HPP
#define VMM_X64_PLATFORM_SEAM_HPP

#include <vmm/platform/x64/x64_platform.hpp>

namespace vmm
{

template<
    class acpi_type,
    class loader_type,
    class memory_concrete_type
>
class x64_platform_seam :
    public x64_platform
{
public:

    // ---------------------------- acpi seam ----------------------------------
    uintptr_t get_acpi_rsdp_hpa() noexcept final
    { return m_acpi_type.get_acpi_rsdp_hpa(); }

    uintptr_t get_acpi_dmar_hpa() noexcept final
    { return m_acpi_type.get_acpi_dmar_hpa(); }

    // --------------------------- loader seam ---------------------------------
    uintptr_t get_loader_wakeup_entry_point_hpa() noexcept final
    { return m_loader_type.get_loader_wakeup_entry_point_hpa(); }

    bool is_late_launch() noexcept final
    { return m_loader_type.is_late_launch(); }

    // --------------------------- memory seam ---------------------------------
    void * alloc_hva_map(uintptr_t hpa, uintmax_t size, page_size ps, memory_type mt) noexcept final
    { return m_memory_type.alloc_hva_map(hpa, size, ps, mt); }

    uintptr_t hva_to_hpa(void * hva) noexcept final
    { return m_memory_type.hva_to_hpa(hva); }

private:
    acpi_type m_acpi_type;
    loader_type m_loader_type;
    memory_concrete_type m_memory_type;
};

}

#endif
