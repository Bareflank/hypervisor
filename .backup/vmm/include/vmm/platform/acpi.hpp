#ifndef VMM_MEMORY_ACPI_HPP
#define VMM_MEMORY_ACPI_HPP

#include <bsl/cstdint.hpp>

namespace vmm
{

class acpi
{
public:

    /// @brief Returns the base host physical address of the ACPI Root System
    ///     Descriptor Table (RSDP), or 0 if it does not exist
    ///
    /// @return The host physical address of the RSDP, or 0 if it does not exist
    virtual uintptr_t get_acpi_rsdp_hpa() noexcept = 0;

    /// @brief Returns the base host physical address of the ACPI DMA Remapping
    ///     Reporting Structure (DMAR), or 0 if it does not exist
    ///
    /// @return The host physical address of the DMAR, or 0 if it does not exist
    virtual uintptr_t get_acpi_dmar_hpa() noexcept = 0;

    virtual ~acpi() noexcept = default;
protected:
    acpi() noexcept = default;
    acpi(acpi &&) noexcept = default;
    acpi &operator=(acpi &&) noexcept = default;
    acpi(acpi const &) = delete;
    acpi &operator=(acpi const &) & = delete;
};

}

#endif
