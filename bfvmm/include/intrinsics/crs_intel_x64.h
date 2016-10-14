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

#ifndef CRS_INTEL_X64_H
#define CRS_INTEL_X64_H

extern "C" uint64_t __read_cr0(void) noexcept;
extern "C" void __write_cr0(uint64_t val) noexcept;

extern "C" uint64_t __read_cr3(void) noexcept;
extern "C" void __write_cr3(uint64_t val) noexcept;

extern "C" uint64_t __read_cr4(void) noexcept;
extern "C" void __write_cr4(uint64_t val) noexcept;

// *INDENT-OFF*

namespace intel_x64
{
namespace cr0
{
    inline auto get() noexcept
    { return __read_cr0(); }

    template<class T> void set(T val) noexcept
    { __write_cr0(val); }

    namespace protection_enable
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "protection_enable";

        inline auto get() noexcept
        { return (__read_cr0() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr0((__read_cr0() & ~mask) | ((val << from) & mask)); }
    }

    namespace monitor_coprocessor
    {
        constexpr const auto mask = 0x0000000000000002UL;
        constexpr const auto from = 1;
        constexpr const auto name = "monitor_coprocessor";

        inline auto get() noexcept
        { return (__read_cr0() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr0((__read_cr0() & ~mask) | ((val << from) & mask)); }
    }

    namespace emulation
    {
        constexpr const auto mask = 0x0000000000000004UL;
        constexpr const auto from = 2;
        constexpr const auto name = "emulation";

        inline auto get() noexcept
        { return (__read_cr0() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr0((__read_cr0() & ~mask) | ((val << from) & mask)); }
    }

    namespace task_switched
    {
        constexpr const auto mask = 0x0000000000000008UL;
        constexpr const auto from = 3;
        constexpr const auto name = "task_switched";

        inline auto get() noexcept
        { return (__read_cr0() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr0((__read_cr0() & ~mask) | ((val << from) & mask)); }
    }

    namespace extension_type
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "extension_type";

        inline auto get() noexcept
        { return (__read_cr0() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr0((__read_cr0() & ~mask) | ((val << from) & mask)); }
    }

    namespace numeric_error
    {
        constexpr const auto mask = 0x0000000000000020UL;
        constexpr const auto from = 5;
        constexpr const auto name = "numeric_error";

        inline auto get() noexcept
        { return (__read_cr0() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr0((__read_cr0() & ~mask) | ((val << from) & mask)); }
    }

    namespace write_protect
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "write_protect";

        inline auto get() noexcept
        { return (__read_cr0() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr0((__read_cr0() & ~mask) | ((val << from) & mask)); }
    }

    namespace alignment_mask
    {
        constexpr const auto mask = 0x0000000000040000UL;
        constexpr const auto from = 18;
        constexpr const auto name = "alignment_mask";

        inline auto get() noexcept
        { return (__read_cr0() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr0((__read_cr0() & ~mask) | ((val << from) & mask)); }
    }

    namespace not_write_through
    {
        constexpr const auto mask = 0x0000000020000000UL;
        constexpr const auto from = 29;
        constexpr const auto name = "not_write_through";

        inline auto get() noexcept
        { return (__read_cr0() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr0((__read_cr0() & ~mask) | ((val << from) & mask)); }
    }

    namespace cache_disable
    {
        constexpr const auto mask = 0x0000000040000000UL;
        constexpr const auto from = 30;
        constexpr const auto name = "cache_disable";

        inline auto get() noexcept
        { return (__read_cr0() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr0((__read_cr0() & ~mask) | ((val << from) & mask)); }
    }

    namespace paging
    {
        constexpr const auto mask = 0x0000000080000000UL;
        constexpr const auto from = 31;
        constexpr const auto name = "paging";

        inline auto get() noexcept
        { return (__read_cr0() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr0((__read_cr0() & ~mask) | ((val << from) & mask)); }
    }
}

namespace cr3
{
    inline auto get() noexcept
    { return __read_cr3(); }

    template<class T> void set(T val) noexcept
    { __write_cr3(val); }
}

namespace cr4
{
    inline auto get() noexcept
    { return __read_cr4(); }

    template<class T> void set(T val) noexcept
    { __write_cr4(val); }

    namespace v8086_mode_extensions
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "v8086_mode_extensions";

        inline auto get() noexcept
        { return (__read_cr4() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr4((__read_cr4() & ~mask) | ((val << from) & mask)); }
    }

    namespace protected_mode_virtual_interrupts
    {
        constexpr const auto mask = 0x0000000000000002UL;
        constexpr const auto from = 1;
        constexpr const auto name = "protected_mode_virtual_interrupts";

        inline auto get() noexcept
        { return (__read_cr4() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr4((__read_cr4() & ~mask) | ((val << from) & mask)); }
    }

    namespace time_stamp_disable
    {
        constexpr const auto mask = 0x0000000000000004UL;
        constexpr const auto from = 2;
        constexpr const auto name = "time_stamp_disable";

        inline auto get() noexcept
        { return (__read_cr4() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr4((__read_cr4() & ~mask) | ((val << from) & mask)); }
    }

    namespace debugging_extensions
    {
        constexpr const auto mask = 0x0000000000000008UL;
        constexpr const auto from = 3;
        constexpr const auto name = "debugging_extensions";

        inline auto get() noexcept
        { return (__read_cr4() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr4((__read_cr4() & ~mask) | ((val << from) & mask)); }
    }

    namespace page_size_extensions
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "page_size_extensions";

        inline auto get() noexcept
        { return (__read_cr4() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr4((__read_cr4() & ~mask) | ((val << from) & mask)); }
    }

    namespace physical_address_extensions
    {
        constexpr const auto mask = 0x0000000000000020UL;
        constexpr const auto from = 5;
        constexpr const auto name = "physical_address_extensions";

        inline auto get() noexcept
        { return (__read_cr4() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr4((__read_cr4() & ~mask) | ((val << from) & mask)); }
    }

    namespace machine_check_enable
    {
        constexpr const auto mask = 0x0000000000000040UL;
        constexpr const auto from = 6;
        constexpr const auto name = "machine_check_enable";

        inline auto get() noexcept
        { return (__read_cr4() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr4((__read_cr4() & ~mask) | ((val << from) & mask)); }
    }

    namespace page_global_enable
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "page_global_enable";

        inline auto get() noexcept
        { return (__read_cr4() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr4((__read_cr4() & ~mask) | ((val << from) & mask)); }
    }

    namespace performance_monitor_counter_enable
    {
        constexpr const auto mask = 0x0000000000000100UL;
        constexpr const auto from = 8;
        constexpr const auto name = "performance_monitor_counter_enable";

        inline auto get() noexcept
        { return (__read_cr4() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr4((__read_cr4() & ~mask) | ((val << from) & mask)); }
    }

    namespace osfxsr
    {
        constexpr const auto mask = 0x0000000000000200UL;
        constexpr const auto from = 9;
        constexpr const auto name = "osfxsr";

        inline auto get() noexcept
        { return (__read_cr4() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr4((__read_cr4() & ~mask) | ((val << from) & mask)); }
    }

    namespace osxmmexcpt
    {
        constexpr const auto mask = 0x0000000000000400UL;
        constexpr const auto from = 10;
        constexpr const auto name = "osxmmexcpt";

        inline auto get() noexcept
        { return (__read_cr4() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr4((__read_cr4() & ~mask) | ((val << from) & mask)); }
    }

    namespace vmx_enable_bit
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "vmx_enable_bit";

        inline auto get() noexcept
        { return (__read_cr4() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr4((__read_cr4() & ~mask) | ((val << from) & mask)); }
    }

    namespace smx_enable_bit
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "smx_enable_bit";

        inline auto get() noexcept
        { return (__read_cr4() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr4((__read_cr4() & ~mask) | ((val << from) & mask)); }
    }

    namespace fsgsbase_enable_bit
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "fsgsbase_enable_bit";

        inline auto get() noexcept
        { return (__read_cr4() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr4((__read_cr4() & ~mask) | ((val << from) & mask)); }
    }

    namespace pcid_enable_bit
    {
        constexpr const auto mask = 0x0000000000020000UL;
        constexpr const auto from = 17;
        constexpr const auto name = "pcid_enable_bit";

        inline auto get() noexcept
        { return (__read_cr4() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr4((__read_cr4() & ~mask) | ((val << from) & mask)); }
    }

    namespace osxsave
    {
        constexpr const auto mask = 0x0000000000040000UL;
        constexpr const auto from = 18;
        constexpr const auto name = "osxsave";

        inline auto get() noexcept
        { return (__read_cr4() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr4((__read_cr4() & ~mask) | ((val << from) & mask)); }
    }

    namespace smep_enable_bit
    {
        constexpr const auto mask = 0x0000000000100000UL;
        constexpr const auto from = 20;
        constexpr const auto name = "smep_enable_bit";

        inline auto get() noexcept
        { return (__read_cr4() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr4((__read_cr4() & ~mask) | ((val << from) & mask)); }
    }

    namespace smap_enable_bit
    {
        constexpr const auto mask = 0x0000000000200000UL;
        constexpr const auto from = 21;
        constexpr const auto name = "smap_enable_bit";

        inline auto get() noexcept
        { return (__read_cr4() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr4((__read_cr4() & ~mask) | ((val << from) & mask)); }
    }

    namespace protection_key_enable_bit
    {
        constexpr const auto mask = 0x0000000000400000UL;
        constexpr const auto from = 22;
        constexpr const auto name = "protection_key_enable_bit";

        inline auto get() noexcept
        { return (__read_cr4() & mask) >> from; }

        template<class T> void set(T val) noexcept
        { __write_cr4((__read_cr4() & ~mask) | ((val << from) & mask)); }
    }
}
}

#endif

