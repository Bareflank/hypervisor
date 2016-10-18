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

#include <gsl/gsl>

#include <vector>
#include <intrinsics/intrinsics_x64.h>

// -----------------------------------------------------------------------------
// Global Descriptor Table Register
// -----------------------------------------------------------------------------

#pragma pack(push, 1)

struct gdt_reg_x64_t
{
    uint16_t limit;
    uint64_t *base;

    gdt_reg_x64_t() noexcept :
        limit(0),
        base(nullptr)
    {}
};

#pragma pack(pop)

// -----------------------------------------------------------------------------
// Intrinsics
// -----------------------------------------------------------------------------

extern "C" void __read_gdt(gdt_reg_x64_t *gdt_reg) noexcept;
extern "C" void __write_gdt(gdt_reg_x64_t *gdt_reg) noexcept;

// -----------------------------------------------------------------------------
// GDT Functions
// -----------------------------------------------------------------------------

// *INDENT-OFF*

namespace x64
{
namespace gdt
{
    inline auto get() noexcept
    {
        gdt_reg_x64_t reg;
        __read_gdt(&reg);

        return reg;
    }

    template<class B, class L> void set(B base, L limit) noexcept
    {
        gdt_reg_x64_t reg;

        reg.base = base;
        reg.limit = gsl::narrow_cast<uint16_t>(limit);

        __write_gdt(&reg);
    }

    namespace base
    {
        inline auto get() noexcept
        {
            gdt_reg_x64_t reg;
            __read_gdt(&reg);

            return reg.base;
        }

        template<class T> void set(T val) noexcept
        {
            gdt_reg_x64_t reg;
            __read_gdt(&reg);

            reg.base = val;
            __write_gdt(&reg);
        }
    }

    namespace limit
    {
        inline auto get() noexcept
        {
            gdt_reg_x64_t reg;
            __read_gdt(&reg);

            return reg.limit;
        }

        template<class T> void set(T val) noexcept
        {
            gdt_reg_x64_t reg;
            __read_gdt(&reg);

            reg.limit = gsl::narrow_cast<uint16_t>(val);
            __write_gdt(&reg);
        }
    }
}
}

// -----------------------------------------------------------------------------
// Global Descriptor Table
// -----------------------------------------------------------------------------

/// Global Descriptor Table
///
/// This class provides an abstraction around the global descriptor table
/// for 64bit.
///
/// This class does not provide a "descriptor" class as the amount of code
/// needed to completely abstract each descriptor type would be enormous
/// for something that is setup once, and never touched again. So it is
/// left to the user to understand how to set the access rights for each
/// descriptor manually, as this is the part that is descriptor specific.
/// In general, all of the information about each descriptor can be found
/// in the Intel Manual in Volume 3.
///
/// Generally speaking, there are 2 different types of descriptors, a
/// code/data segment descriptor, and a TSS descriptor.
///
/// A code/data segment descriptor is a descriptor that is loaded into
/// es, cs, ss, ds, fs or gs. Information about these types of descriptors
/// can be found in Volume 3, section 3.4.5. A code segment is any
/// segment that is loaded into CS. Although not called out in all of the
/// documentation, Intel does have a stack segment which is any descriptor
/// loaded into SS, and the access rights are different for a stack segment.
/// Finally there are data segments which are any descriptor loaded into
/// es, ds, fs and gs. On 64bit, es and ds are not available, so they should
/// always point to the NULL descriptor, which is the first descriptor in the
/// table, which has to be set to all 0s (per the spec). The only parts of
/// cs, ss, fs, and gs that are used are the access rights. The CPU in
/// 64bit mode assumes that the base is set to 0, and the limit is 0xFFFFF.
/// Although the limit is only 4G (because it's only 20 bits), the CPU
/// internally sets the limit to 2^64 for you. fs and gs are the only segments
/// that can have a base address not set to 0, but they cannot be set using
/// the GDT, and instead have to be set using the MSRs. Bareflank uses
/// gs to store the offset into the state save area for the exit handler.
///
/// A TSS descriptor defines the task state segment. This is a structure
/// that is defined 7.2 (for 32bit), and 7.7 (for 64bit). The OS might
/// fill in this structure for syscalls, but in general, this structure
/// is not used in 64bit, but still needs to be defined. For a hypervisor,
/// this structure can be left blank. The base address of the TSS descriptor
/// needs to be the address of the TSS, the limit should be sizeof(TSS), which
/// for a hypervisor that doesn't use the IO bitmap, or any custom data is
/// 104 bytes, and the access rights are set to a present 64bit TSS. There
/// is one complication with the TSS descriptor which is that you cannot
/// simply call ltr (load task register) with any TSS. The TSS cannot have
/// the busy flags set. Since there is a TSS that the host OS has, and a
/// TSS for the VMM, this tends to be fine, up to the point where the
/// VMM attempts to promote the guest. When this happens, there are actually
/// two TSS descriptors marked as busy, which should never happen, but does.
/// The solution is to mark the host OS's TSS descriptor as not busy
/// manually before loading it.
///
class gdt_x64
{
public:

    /// Constructor
    ///
    /// Creates a GDT based on the GDT currently in hardware.
    ///
    /// @note This copies the current GDT. Therefore, the set functions do not
    ///     modify the GDT that is in hardware, but instead modify the copy.
    ///     If you want to modify the GDT that is in hardware, create a new
    ///     GDT using an alternate constructor, and set the hardware to use
    ///     that GDT instead.
    ///
    gdt_x64();

    /// Constructor
    ///
    /// Creates a new GDT, with size defining the number of descriptors
    /// in the GDT.
    ///
    /// @param size number of entries in the GDT
    ///
    gdt_x64(uint16_t size);

    /// Destructor
    ///
    ~gdt_x64() noexcept = default;

    /// GDT Base Address
    ///
    /// @return returns the base address of the GDT itself.
    ///
    auto base() const
    { return reinterpret_cast<uint64_t>(m_gdt_reg.base); }

    /// GDT Limit
    ///
    /// @return returns the size of the GDT itself in bytes
    ///
    auto limit() const
    { return m_gdt_reg.limit; }

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
    void set_base(uint16_t index, uint64_t addr);

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
    uint64_t base(uint16_t index) const;

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
    void set_limit(uint16_t index, uint32_t limit);

    /// Get Descriptor Limit
    ///
    /// Gets the descriptors limit.
    ///
    /// @param index the index of the GDT descriptor
    /// @return the descriptors limit
    ///
    uint32_t limit(uint16_t index) const;

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
    void set_access_rights(uint16_t index, uint32_t access_rights);

    /// Get Descriptor Access Rights
    ///
    /// Gets the access rights for the descriptor
    ///
    /// @param index the index of the GDT descriptor
    /// @return the descriptors access rights
    ///
    uint32_t access_rights(uint16_t index) const;

private:

    friend class intrinsics_ut;

    gdt_reg_x64_t m_gdt_reg;
    std::vector<uint64_t> m_gdt;
};

#endif
