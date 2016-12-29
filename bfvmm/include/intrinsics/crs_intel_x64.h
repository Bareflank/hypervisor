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

#include <debug.h>
#include <bitmanip.h>

extern "C" uint64_t __read_cr0(void) noexcept;
extern "C" void __write_cr0(uint64_t val) noexcept;

extern "C" uint64_t __read_cr2(void) noexcept;
extern "C" void __write_cr2(uint64_t val) noexcept;

extern "C" uint64_t __read_cr3(void) noexcept;
extern "C" void __write_cr3(uint64_t val) noexcept;

extern "C" uint64_t __read_cr4(void) noexcept;
extern "C" void __write_cr4(uint64_t val) noexcept;

// *INDENT-OFF*

namespace intel_x64
{
namespace cr0
{
    using value_type = uint64_t;

    inline auto get() noexcept
    { return __read_cr0(); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) noexcept { __write_cr0(val); }

    namespace protection_enable
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "protection_enable";

        inline auto get() noexcept
        { return get_bit(__read_cr0(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr0(val ? set_bit(__read_cr0(), from) : clear_bit(__read_cr0(), from)); }
    }

    namespace monitor_coprocessor
    {
        constexpr const auto mask = 0x0000000000000002UL;
        constexpr const auto from = 1;
        constexpr const auto name = "monitor_coprocessor";

        inline auto get() noexcept
        { return get_bit(__read_cr0(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr0(val ? set_bit(__read_cr0(), from) : clear_bit(__read_cr0(), from)); }
    }

    namespace emulation
    {
        constexpr const auto mask = 0x0000000000000004UL;
        constexpr const auto from = 2;
        constexpr const auto name = "emulation";

        inline auto get() noexcept
        { return get_bit(__read_cr0(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr0(val ? set_bit(__read_cr0(), from) : clear_bit(__read_cr0(), from)); }
    }

    namespace task_switched
    {
        constexpr const auto mask = 0x0000000000000008UL;
        constexpr const auto from = 3;
        constexpr const auto name = "task_switched";

        inline auto get() noexcept
        { return get_bit(__read_cr0(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr0(val ? set_bit(__read_cr0(), from) : clear_bit(__read_cr0(), from)); }
    }

    namespace extension_type
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "extension_type";

        inline auto get() noexcept
        { return get_bit(__read_cr0(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr0(val ? set_bit(__read_cr0(), from) : clear_bit(__read_cr0(), from)); }
    }

    namespace numeric_error
    {
        constexpr const auto mask = 0x0000000000000020UL;
        constexpr const auto from = 5;
        constexpr const auto name = "numeric_error";

        inline auto get() noexcept
        { return get_bit(__read_cr0(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr0(val ? set_bit(__read_cr0(), from) : clear_bit(__read_cr0(), from)); }
    }

    namespace write_protect
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "write_protect";

        inline auto get() noexcept
        { return get_bit(__read_cr0(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr0(val ? set_bit(__read_cr0(), from) : clear_bit(__read_cr0(), from)); }
    }

    namespace alignment_mask
    {
        constexpr const auto mask = 0x0000000000040000UL;
        constexpr const auto from = 18;
        constexpr const auto name = "alignment_mask";

        inline auto get() noexcept
        { return get_bit(__read_cr0(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr0(val ? set_bit(__read_cr0(), from) : clear_bit(__read_cr0(), from)); }
    }

    namespace not_write_through
    {
        constexpr const auto mask = 0x0000000020000000UL;
        constexpr const auto from = 29;
        constexpr const auto name = "not_write_through";

        inline auto get() noexcept
        { return get_bit(__read_cr0(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr0(val ? set_bit(__read_cr0(), from) : clear_bit(__read_cr0(), from)); }
    }

    namespace cache_disable
    {
        constexpr const auto mask = 0x0000000040000000UL;
        constexpr const auto from = 30;
        constexpr const auto name = "cache_disable";

        inline auto get() noexcept
        { return get_bit(__read_cr0(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr0(val ? set_bit(__read_cr0(), from) : clear_bit(__read_cr0(), from)); }
    }

    namespace paging
    {
        constexpr const auto mask = 0x0000000080000000UL;
        constexpr const auto from = 31;
        constexpr const auto name = "paging";

        inline auto get() noexcept
        { return get_bit(__read_cr0(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr0(val ? set_bit(__read_cr0(), from) : clear_bit(__read_cr0(), from)); }
    }

    inline void dump() noexcept
    {
        bfdebug << "cr0 enabled flags:" << bfendl;

        if (protection_enable::get())
            bfdebug << "    - " << protection_enable::name << bfendl;
        if (monitor_coprocessor::get())
            bfdebug << "    - " << monitor_coprocessor::name << bfendl;
        if (emulation::get())
            bfdebug << "    - " << emulation::name << bfendl;
        if (task_switched::get())
            bfdebug << "    - " << task_switched::name << bfendl;
        if (extension_type::get())
            bfdebug << "    - " << extension_type::name << bfendl;
        if (numeric_error::get())
            bfdebug << "    - " << numeric_error::name << bfendl;
        if (write_protect::get())
            bfdebug << "    - " << write_protect::name << bfendl;
        if (alignment_mask::get())
            bfdebug << "    - " << alignment_mask::name << bfendl;
        if (not_write_through::get())
            bfdebug << "    - " << not_write_through::name << bfendl;
        if (cache_disable::get())
            bfdebug << "    - " << cache_disable::name << bfendl;
        if (paging::get())
            bfdebug << "    - " << paging::name << bfendl;
    }
}

namespace cr2
{
    using value_type = uint64_t;

    inline auto get() noexcept
    { return __read_cr2(); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) noexcept { __write_cr2(val); }
}

namespace cr3
{
    using value_type = uint64_t;

    inline auto get() noexcept
    { return __read_cr3(); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) noexcept { __write_cr3(val); }
}

namespace cr4
{
    using value_type = uint64_t;

    inline auto get() noexcept
    { return __read_cr4(); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) noexcept { __write_cr4(val); }

    namespace v8086_mode_extensions
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "v8086_mode_extensions";

        inline auto get() noexcept
        { return get_bit(__read_cr4(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr4(val ? set_bit(__read_cr4(), from) : clear_bit(__read_cr4(), from)); }
    }

    namespace protected_mode_virtual_interrupts
    {
        constexpr const auto mask = 0x0000000000000002UL;
        constexpr const auto from = 1;
        constexpr const auto name = "protected_mode_virtual_interrupts";

        inline auto get() noexcept
        { return get_bit(__read_cr4(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr4(val ? set_bit(__read_cr4(), from) : clear_bit(__read_cr4(), from)); }
    }

    namespace time_stamp_disable
    {
        constexpr const auto mask = 0x0000000000000004UL;
        constexpr const auto from = 2;
        constexpr const auto name = "time_stamp_disable";

        inline auto get() noexcept
        { return get_bit(__read_cr4(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr4(val ? set_bit(__read_cr4(), from) : clear_bit(__read_cr4(), from)); }
    }

    namespace debugging_extensions
    {
        constexpr const auto mask = 0x0000000000000008UL;
        constexpr const auto from = 3;
        constexpr const auto name = "debugging_extensions";

        inline auto get() noexcept
        { return get_bit(__read_cr4(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr4(val ? set_bit(__read_cr4(), from) : clear_bit(__read_cr4(), from)); }
    }

    namespace page_size_extensions
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "page_size_extensions";

        inline auto get() noexcept
        { return get_bit(__read_cr4(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr4(val ? set_bit(__read_cr4(), from) : clear_bit(__read_cr4(), from)); }
    }

    namespace physical_address_extensions
    {
        constexpr const auto mask = 0x0000000000000020UL;
        constexpr const auto from = 5;
        constexpr const auto name = "physical_address_extensions";

        inline auto get() noexcept
        { return get_bit(__read_cr4(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr4(val ? set_bit(__read_cr4(), from) : clear_bit(__read_cr4(), from)); }
    }

    namespace machine_check_enable
    {
        constexpr const auto mask = 0x0000000000000040UL;
        constexpr const auto from = 6;
        constexpr const auto name = "machine_check_enable";

        inline auto get() noexcept
        { return get_bit(__read_cr4(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr4(val ? set_bit(__read_cr4(), from) : clear_bit(__read_cr4(), from)); }
    }

    namespace page_global_enable
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "page_global_enable";

        inline auto get() noexcept
        { return get_bit(__read_cr4(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr4(val ? set_bit(__read_cr4(), from) : clear_bit(__read_cr4(), from)); }
    }

    namespace performance_monitor_counter_enable
    {
        constexpr const auto mask = 0x0000000000000100UL;
        constexpr const auto from = 8;
        constexpr const auto name = "performance_monitor_counter_enable";

        inline auto get() noexcept
        { return get_bit(__read_cr4(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr4(val ? set_bit(__read_cr4(), from) : clear_bit(__read_cr4(), from)); }
    }

    namespace osfxsr
    {
        constexpr const auto mask = 0x0000000000000200UL;
        constexpr const auto from = 9;
        constexpr const auto name = "osfxsr";

        inline auto get() noexcept
        { return get_bit(__read_cr4(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr4(val ? set_bit(__read_cr4(), from) : clear_bit(__read_cr4(), from)); }
    }

    namespace osxmmexcpt
    {
        constexpr const auto mask = 0x0000000000000400UL;
        constexpr const auto from = 10;
        constexpr const auto name = "osxmmexcpt";

        inline auto get() noexcept
        { return get_bit(__read_cr4(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr4(val ? set_bit(__read_cr4(), from) : clear_bit(__read_cr4(), from)); }
    }

    namespace vmx_enable_bit
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "vmx_enable_bit";

        inline auto get() noexcept
        { return get_bit(__read_cr4(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr4(val ? set_bit(__read_cr4(), from) : clear_bit(__read_cr4(), from)); }
    }

    namespace smx_enable_bit
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "smx_enable_bit";

        inline auto get() noexcept
        { return get_bit(__read_cr4(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr4(val ? set_bit(__read_cr4(), from) : clear_bit(__read_cr4(), from)); }
    }

    namespace fsgsbase_enable_bit
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "fsgsbase_enable_bit";

        inline auto get() noexcept
        { return get_bit(__read_cr4(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr4(val ? set_bit(__read_cr4(), from) : clear_bit(__read_cr4(), from)); }
    }

    namespace pcid_enable_bit
    {
        constexpr const auto mask = 0x0000000000020000UL;
        constexpr const auto from = 17;
        constexpr const auto name = "pcid_enable_bit";

        inline auto get() noexcept
        { return get_bit(__read_cr4(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr4(val ? set_bit(__read_cr4(), from) : clear_bit(__read_cr4(), from)); }
    }

    namespace osxsave
    {
        constexpr const auto mask = 0x0000000000040000UL;
        constexpr const auto from = 18;
        constexpr const auto name = "osxsave";

        inline auto get() noexcept
        { return get_bit(__read_cr4(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr4(val ? set_bit(__read_cr4(), from) : clear_bit(__read_cr4(), from)); }
    }

    namespace smep_enable_bit
    {
        constexpr const auto mask = 0x0000000000100000UL;
        constexpr const auto from = 20;
        constexpr const auto name = "smep_enable_bit";

        inline auto get() noexcept
        { return get_bit(__read_cr4(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr4(val ? set_bit(__read_cr4(), from) : clear_bit(__read_cr4(), from)); }
    }

    namespace smap_enable_bit
    {
        constexpr const auto mask = 0x0000000000200000UL;
        constexpr const auto from = 21;
        constexpr const auto name = "smap_enable_bit";

        inline auto get() noexcept
        { return get_bit(__read_cr4(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr4(val ? set_bit(__read_cr4(), from) : clear_bit(__read_cr4(), from)); }
    }

    namespace protection_key_enable_bit
    {
        constexpr const auto mask = 0x0000000000400000UL;
        constexpr const auto from = 22;
        constexpr const auto name = "protection_key_enable_bit";

        inline auto get() noexcept
        { return get_bit(__read_cr4(), from) != 0; }

        inline void set(bool val) noexcept
        { __write_cr4(val ? set_bit(__read_cr4(), from) : clear_bit(__read_cr4(), from)); }
    }

    inline void dump() noexcept
    {
        bfdebug << "cr4 enabled flags:" << bfendl;

        if (v8086_mode_extensions::get())
            bfdebug << "    - " << v8086_mode_extensions::name << bfendl;
        if (protected_mode_virtual_interrupts::get())
            bfdebug << "    - " << protected_mode_virtual_interrupts::name << bfendl;
        if (time_stamp_disable::get())
            bfdebug << "    - " << time_stamp_disable::name << bfendl;
        if (debugging_extensions::get())
            bfdebug << "    - " << debugging_extensions::name << bfendl;
        if (page_size_extensions::get())
            bfdebug << "    - " << page_size_extensions::name << bfendl;
        if (physical_address_extensions::get())
            bfdebug << "    - " << physical_address_extensions::name << bfendl;
        if (machine_check_enable::get())
            bfdebug << "    - " << machine_check_enable::name << bfendl;
        if (page_global_enable::get())
            bfdebug << "    - " << page_global_enable::name << bfendl;
        if (performance_monitor_counter_enable::get())
            bfdebug << "    - " << performance_monitor_counter_enable::name << bfendl;
        if (osfxsr::get())
            bfdebug << "    - " << osfxsr::name << bfendl;
        if (osxmmexcpt::get())
            bfdebug << "    - " << osxmmexcpt::name << bfendl;
        if (vmx_enable_bit::get())
            bfdebug << "    - " << vmx_enable_bit::name << bfendl;
        if (smx_enable_bit::get())
            bfdebug << "    - " << smx_enable_bit::name << bfendl;
        if (smx_enable_bit::get())
            bfdebug << "    - " << smx_enable_bit::name << bfendl;
        if (fsgsbase_enable_bit::get())
            bfdebug << "    - " << fsgsbase_enable_bit::name << bfendl;
        if (pcid_enable_bit::get())
            bfdebug << "    - " << pcid_enable_bit::name << bfendl;
        if (osxsave::get())
            bfdebug << "    - " << osxsave::name << bfendl;
        if (smep_enable_bit::get())
            bfdebug << "    - " << smep_enable_bit::name << bfendl;
        if (smap_enable_bit::get())
            bfdebug << "    - " << smap_enable_bit::name << bfendl;
        if (protection_key_enable_bit::get())
            bfdebug << "    - " << protection_key_enable_bit::name << bfendl;
    }
}
}

// *INDENT-ON*

#endif
