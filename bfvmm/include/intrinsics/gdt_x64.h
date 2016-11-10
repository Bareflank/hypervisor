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
#include <algorithm>
#include <exception>

// -----------------------------------------------------------------------------
// Global Descriptor Table Register
// -----------------------------------------------------------------------------

#pragma pack(push, 1)

struct gdt_reg_x64_t
{
    using limit_type = uint16_t;
    using base_type = uint64_t *;

    limit_type limit;
    base_type base;

    gdt_reg_x64_t() noexcept :
        limit(0),
        base(nullptr)
    {}

    gdt_reg_x64_t(base_type b, limit_type l) noexcept :
        limit(l),
        base(b)
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
        auto &&reg = gdt_reg_x64_t{};
        __read_gdt(&reg);

        return reg;
    }

    inline void set(gdt_reg_x64_t::base_type base, gdt_reg_x64_t::limit_type limit) noexcept
    {
        auto &&reg = gdt_reg_x64_t{base, limit};
        __write_gdt(&reg);
    }

    namespace base
    {
        inline auto get() noexcept
        {
            auto &&reg = gdt_reg_x64_t{};
            __read_gdt(&reg);

            return reg.base;
        }

        inline void set(gdt_reg_x64_t::base_type base) noexcept
        {
            auto &&reg = gdt_reg_x64_t{};
            __read_gdt(&reg);

            reg.base = base;
            __write_gdt(&reg);
        }
    }

    namespace limit
    {
        inline auto get() noexcept
        {
            auto &&reg = gdt_reg_x64_t{};
            __read_gdt(&reg);

            return reg.limit;
        }

        inline void set(gdt_reg_x64_t::limit_type limit) noexcept
        {
            auto &&reg = gdt_reg_x64_t{};
            __read_gdt(&reg);

            reg.limit = limit;
            __write_gdt(&reg);
        }
    }
}
}

// *INDENT-ON*

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

    using size_type = uint16_t;
    using index_type = uint16_t;
    using integer_pointer = uintptr_t;
    using base_type = uint64_t;
    using limit_type = uint32_t;
    using access_rights_type = uint32_t;
    using segment_descriptor_type = uint64_t;

    /// Constructor
    ///
    /// Creates a GDT based on the GDT currently in hardware.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @note This copies the current GDT. Therefore, the set functions do not
    ///     modify the GDT that is in hardware, but instead modify the copy.
    ///     If you want to modify the GDT that is in hardware, create a new
    ///     GDT using an alternate constructor, and set the hardware to use
    ///     that GDT instead.
    ///
    gdt_x64()
    {
        m_gdt_reg.base = x64::gdt::base::get();
        m_gdt_reg.limit = x64::gdt::limit::get();

        std::copy_n(m_gdt_reg.base, m_gdt_reg.limit >> 3, std::back_inserter(m_gdt));
    }

    /// Constructor
    ///
    /// Creates a new GDT, with size defining the number of descriptors
    /// in the GDT.
    ///
    /// @expects size != 0;
    /// @ensures none
    ///
    /// @param size number of entries in the GDT
    ///
    gdt_x64(size_type size) :
        m_gdt(size)
    {
        expects(size != 0);

        m_gdt_reg.base = m_gdt.data();
        m_gdt_reg.limit = gsl::narrow<size_type>(size << 3);
    }

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~gdt_x64() noexcept = default;

    /// GDT Base Address
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the base address of the GDT itself.
    ///
    integer_pointer base() const
    { return reinterpret_cast<integer_pointer>(m_gdt_reg.base); }

    /// GDT Limit
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the size of the GDT itself in bytes
    ///
    size_type limit() const
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
    /// @expects index != 0
    /// @expects index < m_gdt.size()
    /// @expects index < m_gdt.size() + 1 (if system descriptor)
    /// @ensures none
    ///
    /// @param index the index of the GDT descriptor
    /// @param addr the base address. For code/data descriptor this needs to
    ///     be 0, and for a TSS this is a 64bit virtual address.
    ///
    void set_base(index_type index, base_type base)
    {
        segment_descriptor_type sd1 = 0;
        segment_descriptor_type sd2 = 0;

        expects(index != 0);
        expects(index < m_gdt.size());

        sd1 = m_gdt.at(index);
        sd1 = (sd1 & 0x00FFFF000000FFFF);

        // The segment base description can be found in the Intel's software
        // developer's manual, volume 3, chapter 3.4.5 as well as volume 3,
        // chapter 24.4.1.
        //
        // Note that in 64bit mode, system descriptors are 16 bytes long
        // instead of the traditional 8 bytes. A system descriptor has the
        // system flag set to 0. Most of the time, this is going to be the
        // TSS descriptor. Even though Intel Tasks don't exist in 64 bit mode,
        // the TSS descriptor is still used, and thus, TR must still be loaded.
        //
        // ------------------------------------------------------------------
        // |                       Base 63-32                               |
        // ------------------------------------------------------------------
        // |   Base 31-24   |                              |   Base 23-16   |
        // ------------------------------------------------------------------
        // |          Base 15-00         |                                  |
        // ------------------------------------------------------------------
        //

        segment_descriptor_type base_15_00 = ((base & 0x000000000000FFFF) << 16);
        segment_descriptor_type base_23_16 = ((base & 0x0000000000FF0000) << 16);
        segment_descriptor_type base_31_24 = ((base & 0x00000000FF000000) << 32);
        segment_descriptor_type base_63_32 = ((base & 0xFFFFFFFF00000000) >> 32);

        if ((sd1 & 0x100000000000) == 0)
        {
            expects(index + 1U < m_gdt.size());

            sd2 = m_gdt.at(index + 1U);
            sd2 = (sd2 & 0xFFFFFFFF00000000);

            m_gdt.at(index + 0U) = sd1 | base_31_24 | base_23_16 | base_15_00;
            m_gdt.at(index + 1U) = sd2 | base_63_32;
        }
        else
        {
            m_gdt.at(index + 0U) = sd1 | base_31_24 | base_23_16 | base_15_00;
        }
    }

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
    /// @expects index != 0
    /// @expects index < m_gdt.size()
    /// @expects index < m_gdt.size() + 1 (if system descriptor)
    /// @ensures none
    ///
    /// @param index the index of the GDT descriptor
    /// @return the base address
    ///
    base_type base(index_type index) const
    {
        segment_descriptor_type sd1 = 0;
        segment_descriptor_type sd2 = 0;

        expects(index != 0);
        expects(index < m_gdt.size());

        // The segment base description can be found in the Intel's software
        // developer's manual, volume 3, chapter 3.4.5 as well as volume 3,
        // chapter 24.4.1.
        //
        // Note that in 64bit mode, system descriptors are 16 bytes long
        // instead of the traditional 8 bytes. A system descriptor has the
        // system flag set to 0. Most of the time, this is going to be the
        // TSS descriptor. Even though Intel Tasks don't exist in 64 bit mode,
        // the TSS descriptor is still used, and thus, TR must still be loaded.
        //
        // ------------------------------------------------------------------
        // |                       Base 63-32                               |
        // ------------------------------------------------------------------
        // |   Base 31-24   |                              |   Base 23-16   |
        // ------------------------------------------------------------------
        // |          Base 15-00         |                                  |
        // ------------------------------------------------------------------
        //

        sd1 = m_gdt.at(index);
        base_type base_15_00 = ((sd1 & 0x00000000FFFF0000) >> 16);
        base_type base_23_16 = ((sd1 & 0x000000FF00000000) >> 16);
        base_type base_31_24 = ((sd1 & 0xFF00000000000000) >> 32);

        if ((sd1 & 0x100000000000) == 0)
        {
            expects(index + 1U < m_gdt.size());

            sd2 = m_gdt.at(index + 1U);
            base_type base_63_32 = ((sd2 & 0x00000000FFFFFFFF) << 32);

            return base_63_32 | base_31_24 | base_23_16 | base_15_00;
        }

        return base_31_24 | base_23_16 | base_15_00;
    }

    /// Set Descriptor Limit
    ///
    /// Sets the descriptors limit. Note that for code/data descriptors,
    /// this needs to be 0xFFFFF as segmentation is not used in 64bit. For
    /// the TSS, the limit should be the size in bytes of the TSS, and
    /// any other data you wish to store.
    ///
    /// @expects index != 0
    /// @expects index < m_gdt.size()
    /// @ensures none
    ///
    /// @param index the index of the GDT descriptor
    /// @param limit the descriptors limit
    ///
    void set_limit(index_type index, limit_type limit)
    {
        expects(index != 0);
        expects(index < m_gdt.size());

        segment_descriptor_type sd1 = (m_gdt.at(index) & 0xFFF0FFFFFFFF0000);

        // The segment limit description can be found in the Intel's software
        // developer's manual, volume 3, chapter 3.4.5 as well as volume 3,
        // chapter 24.4.1.
        //
        // ------------------------------------------------------------------
        // |               | Limit 19-16 |                                  |
        // ------------------------------------------------------------------
        // |                             |            Limit 15-00           |
        // ------------------------------------------------------------------

        if ((sd1 & 0x80000000000000) != 0)
            limit = (limit >> 12);

        segment_descriptor_type limit_15_00 = ((static_cast<segment_descriptor_type>(limit) & 0x000000000000FFFF) << 0);
        segment_descriptor_type limit_19_16 = ((static_cast<segment_descriptor_type>(limit) & 0x00000000000F0000) << 32);

        m_gdt.at(index) = sd1 | limit_19_16 | limit_15_00;
    }

    /// Get Descriptor Limit
    ///
    /// Gets the descriptors limit.
    ///
    /// @expects index != 0
    /// @expects index < m_gdt.size()
    /// @ensures none
    ///
    /// @param index the index of the GDT descriptor
    /// @return the descriptors limit
    ///
    limit_type limit(index_type index) const
    {
        expects(index != 0);
        expects(index < m_gdt.size());

        segment_descriptor_type sd1 = m_gdt.at(index);

        // The segment limit description can be found in the Intel's software
        // developer's manual, volume 3, chapter 3.4.5 as well as volume 3,
        // chapter 24.4.1.
        //
        // ------------------------------------------------------------------
        // |               | Limit 19-16 |                                  |
        // ------------------------------------------------------------------
        // |                             |            Limit 15-00           |
        // ------------------------------------------------------------------

        if ((sd1 & 0x80000000000000) != 0)
        {
            limit_type limit_15_00 = gsl::narrow_cast<limit_type>((sd1 & 0x000000000000FFFF) >> 0);
            limit_type limit_19_16 = gsl::narrow_cast<limit_type>((sd1 & 0x000F000000000000) >> 32);

            return ((limit_19_16 | limit_15_00) << 12) | 0x0000000000000FFF;
        }

        limit_type limit_15_00 = gsl::narrow_cast<limit_type>((sd1 & 0x000000000000FFFF) >> 0);
        limit_type limit_19_16 = gsl::narrow_cast<limit_type>((sd1 & 0x000F000000000000) >> 32);

        return limit_19_16 | limit_15_00;
    }

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
    /// loading this descriptor), please see the Intel manual.
    ///
    /// @expects index != 0
    /// @expects index < m_gdt.size()
    /// @ensures none
    ///
    /// @param index the index of the GDT descriptor
    /// @param access_rights the access rights for this descriptor
    ///
    void set_access_rights(index_type index, access_rights_type access_rights)
    {
        expects(index != 0);
        expects(index < m_gdt.size());

        segment_descriptor_type sd1 = (m_gdt.at(index) & 0xFF0F00FFFFFFFFFF);

        // The segment access description can be found in the intel's software
        // developer's manual, volume 3, chapter 3.4.5 as well as volume 3,
        // chapter 24.4.1.
        //
        // ------------------------------------------------------------------
        // |           | A 15-12 |       |  Access 07-00   |                |
        // ------------------------------------------------------------------
        // |                             |                                  |
        // ------------------------------------------------------------------
        //

        segment_descriptor_type access_rights_07_00 = ((static_cast<segment_descriptor_type>(access_rights) & 0x00000000000000FF) << 40);
        segment_descriptor_type access_rights_15_12 = ((static_cast<segment_descriptor_type>(access_rights) & 0x000000000000F000) << 40);

        m_gdt.at(index) = sd1 | access_rights_15_12 | access_rights_07_00;
    }

    /// Get Descriptor Access Rights
    ///
    /// Gets the access rights for the descriptor
    ///
    /// @expects index != 0
    /// @expects index < m_gdt.size()
    /// @ensures none
    ///
    /// @param index the index of the GDT descriptor
    /// @return the descriptors access rights
    ///
    access_rights_type access_rights(index_type index) const
    {
        expects(index != 0);
        expects(index < m_gdt.size());

        segment_descriptor_type sd1 = m_gdt.at(index);

        // The segment access description can be found in the Intel's software
        // developer's manual, volume 3, chapter 3.4.5 as well as volume 3,
        // chapter 24.4.1.
        //
        // ------------------------------------------------------------------
        // |           | A 15-12 |       |  Access 07-00   |                |
        // ------------------------------------------------------------------
        // |                             |                                  |
        // ------------------------------------------------------------------
        //

        access_rights_type access_rights_07_00 = static_cast<access_rights_type>((sd1 & 0x0000FF0000000000) >> 40);
        access_rights_type access_rights_15_12 = static_cast<access_rights_type>((sd1 & 0x00F0000000000000) >> 40);

        return access_rights_15_12 | access_rights_07_00;
    }

private:

    friend class intrinsics_ut;

    gdt_reg_x64_t m_gdt_reg;
    std::vector<segment_descriptor_type> m_gdt;
};

#endif
