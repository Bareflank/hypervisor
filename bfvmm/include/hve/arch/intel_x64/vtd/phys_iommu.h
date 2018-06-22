//
// Bareflank Hypervisor
// Copyright (C) 2018 Assured Information Security, Inc.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
//

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-reinterpret-cast
//
// Reason:
//     Although in general this is a good rule, for hypervisor level code that
//     interfaces with the kernel, and raw hardware, this rule is
//     impractical.
//

#ifndef PHYS_IOMMU_INTEL_X64_H
#define PHYS_IOMMU_INTEL_X64_H

#include <stdint.h>
#include <bfgsl.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace vtd
{

/// phys_iommu
///
/// Provides an interface for accessing a physical IOMMU
///
class phys_iommu
{

public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param base the base linear address of the phys_iommu
    ///
    phys_iommu(uintptr_t base) : m_base(base) { }

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~phys_iommu() = default;

    /// Read a 32-bit register at the offset @param offset
    ///
    /// @expects
    /// @ensures
    ///
    /// @param offset the register's offset from the phys_iommu base address
    ///
    /// @return Returns the register's value
    ///
    inline uint32_t read_32(uint32_t offset)
    { return *reinterpret_cast<uint32_t *>(m_base + offset); }

    /// Read a 64-bit register at the offset @param offset
    ///
    /// @expects
    /// @ensures
    ///
    /// @param offset the register's offset from the phys_iommu base address
    ///
    /// @return Returns the register's value
    ///
    inline uint64_t read_64(uint64_t offset)
    { return *reinterpret_cast<uint64_t *>(m_base + offset); }

    /// Write the value @param val to a 32-bit register at the offset
    /// @param offset
    ///
    /// @expects
    /// @ensures
    ///
    /// @param offset the register's offset from the phys_iommu base address
    /// @param val the value to be written
    ///
    inline void write_32(uint32_t offset, uint32_t val)
    { *reinterpret_cast<uint32_t *>(m_base + offset) = val; }

    /// Write the value @param val to a 32-bit register at the offset
    /// @param offset while preserving the current value of all bits described
    /// by @param mask
    ///
    /// @expects
    /// @ensures
    ///
    /// @param offset the register's offset from the phys_iommu base address
    /// @param val the value to be written
    /// @param mask a bitmask of all bits to be preserved during the write
    ///
    inline void write_32_preserved(uint32_t offset, uint32_t val, uint32_t mask)
    { write_32(offset, (read_32(offset) & mask) | (val & ~mask )); }

    /// Write the value @param val to a 64-bit register at the offset
    /// @param offset
    ///
    /// @expects
    /// @ensures
    ///
    /// @param offset the register's offset from the phys_iommu base address
    /// @param val the value to be written
    ///
    inline void write_64(uint64_t offset, uint64_t val)
    { *reinterpret_cast<uint64_t *>(m_base + offset) = val; }

    /// Write the value @param val to a 64-bit register at the offset
    /// @param offset while preserving the current value of all bits described
    /// by @param mask
    ///
    /// @expects
    /// @ensures
    ///
    /// @param offset the register's offset from the phys_iommu base address
    /// @param val the value to be written
    /// @param mask a bitmask of all bits to be preserved during the write
    ///
    inline void write_64_preserved(uint64_t offset, uint64_t val, uint64_t mask)
    { write_64(offset, (read_64(offset) & mask) | (val & ~mask )); }

#ifndef ENABLE_BUILD_TEST
private:
#endif

    uintptr_t m_base;

};

}
}

// *INDENT-ON*

#endif
