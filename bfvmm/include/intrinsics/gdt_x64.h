//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#ifndef GDT_X64_H
#define GDT_X64_H

#include <memory>
#include <functional>
#include <intrinsics/intrinsics_x64.h>

// -----------------------------------------------------------------------------
// Global Descriptor Table Register
// -----------------------------------------------------------------------------

// The CPU gets the base address and limit (number of entries) of the
// global descriptor table by using the lgdt/sgdt instructions, which take
// a memory address that points to the structure below.

#pragma pack(push, 1)

struct gdt_reg_x64_t
{
    uint16_t limit;
    uint64_t base;

    gdt_reg_x64_t() :
        limit(0),
        base(0)
    {}
};

#pragma pack(pop)

// -----------------------------------------------------------------------------
// Global Descriptor Table
// -----------------------------------------------------------------------------

/// Global Descriptor Table
///
/// Talk about why we don't have a descriptor class because these might be
/// a descriptor or a TSS and they are different sizes.
///
class gdt_x64
{
public:

    /// Constructor
    ///
    /// Creates a new GDT, with size defining the number of descriptors
    /// in the GDT.
    ///
    /// @param size number of entries in the GDT
    ///
    gdt_x64(uint16_t size);

    /// Constructor
    ///
    /// Wraps around the GDT that is currently stored in the hardware.
    ///
    /// @param intrinsics the intrinsics class to use
    ///
    gdt_x64(const std::shared_ptr<intrinsics_x64> &intrinsics);

    /// Destructor
    ///
    virtual ~gdt_x64() {}

    /// GDT Base Address
    ///
    /// @return returns the base address of the GDT itself.
    ///
    virtual uint64_t base() const;

    /// GDT Limit
    ///
    /// @return returns the size of the GDT itself in bytes
    ///
    virtual uint16_t limit() const;

    /// Set Descriptor Base Address
    ///
    /// Sets the base address of a descriptor. If the descriptor is a TSS
    /// (determined using the system descriptor flag), the base address is
    /// a 64bit address, and this operation will attempt to touch
    /// 2 64bit descriptor fields. So, if the TSS is at the end of the GDT
    /// (like they usually are) make sure you give yourself space for 2
    /// entries for the TSS, otherwise this code will throw an
    /// invalid_argument exception. Also, since the access rights determine
    /// the descriptor type, make sure you set them first.
    ///
    /// @param index the index of the GDT descriptor
    /// @param addr the base address. For code/data descriptor this needs to
    ///     be 0, and for a TSS this is a 64bit virtual address.
    ///
    virtual void set_base(uint16_t index, uint64_t addr);

    /// Get Descriptor Base Address
    ///
    /// Gets the base address of a descriptor. If the descriptor is a TSS
    /// (determined using the system descriptor flag), the base address is
    /// a 64bit address, and this operation will attempt to touch
    /// 2 64bit descriptor fields. So, if the TSS is at the end of the GDT
    /// (like they usually are) make sure you give yourself space for 2
    /// entries for the TSS, otherwise this code will throw an
    /// invalid_argument exception. Also, since the access rights determine
    /// the descriptor type, make sure you set them first.
    ///
    /// @param index the index of the GDT descriptor
    /// @return the base address
    ///
    virtual uint64_t base(uint16_t index) const;

    /// Set Descriptor Limit
    ///
    /// Sets the descriptors limit. Note that for code/data descriptors,
    /// this needs to be 0xFFFFF as segmentation is not used in 64bit. For
    /// the TSS, the limit should be the size in bytes of the TSS, and
    /// any other data you wish to store.
    ///
    /// @param index the index of the GDT descriptor
    /// @param limit the descriptors limit
    ///
    virtual void set_limit(uint16_t index, uint64_t limit);

    /// Get Descriptor Limit
    ///
    /// Gets the descriptors limit.
    ///
    /// @param index the index of the GDT descriptor
    /// @return the descriptors limit
    ///
    virtual uint64_t limit(uint16_t index) const;

    /// Set Descriptor Access Rights
    ///
    /// Sets the descriptors access rights. Note that Intel defines this
    /// field a little strange. Unlike the base and limit, where the fields
    /// and merged, the access rights leaves the upper "limit" bits in the
    /// access rights, so you have to leave bits 8-11 as 0 as these are
    /// bits 16-19 of the limit field. Also, each bit in the access rights
    /// field has a different meaning based on which segment register is
    /// used. If CS is used, the descriptor is a code segment, if TR is used
    /// the descriptor is a TSS descriptor, if SS is used the segment is a
    /// stack segment, and all others are data segments. For a complete
    /// list of what each bit does (based on what segment register is
    /// loading this descriptor), please see the intel manual.
    ///
    /// @param index the index of the GDT descriptor
    /// @param access_rights the access rights for this descriptor
    ///
    virtual void set_access_rights(uint16_t index, uint64_t access_rights);

    /// Get Descriptor Access Rights
    ///
    /// Gets the access rights for the descriptor
    ///
    /// @param index the index of the GDT descriptor
    /// @return the descriptors access rights
    ///
    virtual uint64_t access_rights(uint16_t index) const;

private:

    uint16_t m_size;
    gdt_reg_x64_t m_gdt_reg;
    std::shared_ptr<uint64_t> m_gdt;
};

#endif // GDT__H
