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

#ifndef IDT_X64_H
#define IDT_X64_H

#include <gsl/gsl>
#include <intrinsics/intrinsics_x64.h>

// -----------------------------------------------------------------------------
// Interrupt Descriptor Table Register
// -----------------------------------------------------------------------------

// The CPU gets the base address and limit (number of entries) of the
// interrupt descriptor table by using the lidt/sidt instructions, which take
// a memory address that points to the structure below.

#pragma pack(push, 1)

struct idt_reg_x64_t
{
    uint16_t limit;
    uint64_t base;

    idt_reg_x64_t() :
        limit(0),
        base(0)
    {}
};

#pragma pack(pop)

// -----------------------------------------------------------------------------
// Interrupt Descriptor Table
// -----------------------------------------------------------------------------

/// Interrupt Descriptor Table
///
/// The interrupt descriptor tables is like the GDT. Each descriptor in
/// 64bit mode is 16 bytes with the upper 64bits containing the upper 32bit
/// offset (like like a TSS descriptor). Unlike the GDT, entry 0 is used,
/// and there "should be" 256 entries, which means it consumes 4k. We left
/// the implementation in a way where you can decide how big you want it, but
/// it really should be 256.
///
/// For more information on the IDT, please see Volume 3, section 6.10
/// of the Intel Manual. For 64bit, see section 6.14.
///
/// Note: For now, the IDT is global, and blank as we have interrupts
///       disabled. At some point when we decide to add support for
///       interrupts we will need to implement this class completely.
///
class idt_x64
{
public:

    /// Constructor
    ///
    /// Creates a new IDT, with size defining the number of descriptors
    /// in the IDT.
    ///
    /// @param size number of entries in the IDT
    ///
    idt_x64(uint16_t size);

    /// Constructor
    ///
    /// Wraps around the IDT that is currently stored in the hardware.
    ///
    /// @param intrinsics the intrinsics class to use
    ///
    idt_x64(const std::shared_ptr<intrinsics_x64> &intrinsics);

    /// Destructor
    ///
    virtual ~idt_x64() = default;

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

private:

    idt_reg_x64_t m_idt_reg;

    gsl::span<uint64_t> m_idt;
    std::unique_ptr<uint64_t[]> m_idt_owner;
};

#endif
