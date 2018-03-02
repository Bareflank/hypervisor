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

#ifndef RFLAGS_X64_H
#define RFLAGS_X64_H

#include <gsl/gsl>

#include <debug.h>
#include <bitmanip.h>

extern "C" uint64_t __read_rflags(void) noexcept;
extern "C" void __write_rflags(uint64_t val) noexcept;

// *INDENT-OFF*

namespace x64
{
namespace rflags
{
    using value_type = uint64_t;

    inline auto get() noexcept
    { return __read_rflags(); }

    namespace carry_flag
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "carry_flag";

        inline auto get() noexcept
        { return get_bit(__read_rflags(), from) != 0; }
    }

    namespace parity_flag
    {
        constexpr const auto mask = 0x0000000000000004UL;
        constexpr const auto from = 2;
        constexpr const auto name = "parity_flag";

        inline auto get() noexcept
        { return get_bit(__read_rflags(), from) != 0; }
    }

    namespace auxiliary_carry_flag
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "auxiliary_carry_flag";

        inline auto get() noexcept
        { return get_bit(__read_rflags(), from) != 0; }
    }

    namespace zero_flag
    {
        constexpr const auto mask = 0x0000000000000040UL;
        constexpr const auto from = 6;
        constexpr const auto name = "zero_flag";

        inline auto get() noexcept
        { return get_bit(__read_rflags(), from) != 0; }
    }

    namespace sign_flag
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "sign_flag";

        inline auto get() noexcept
        { return get_bit(__read_rflags(), from) != 0; }
    }

    namespace trap_flag
    {
        constexpr const auto mask = 0x0000000000000100UL;
        constexpr const auto from = 8;
        constexpr const auto name = "trap_flag";

        inline auto get() noexcept
        { return get_bit(__read_rflags(), from) != 0; }
    }

    namespace interrupt_enable_flag
    {
        constexpr const auto mask = 0x0000000000000200UL;
        constexpr const auto from = 9;
        constexpr const auto name = "interrupt_enable_flag";

        inline auto get() noexcept
        { return get_bit(__read_rflags(), from) != 0; }
    }

    namespace direction_flag
    {
        constexpr const auto mask = 0x0000000000000400UL;
        constexpr const auto from = 10;
        constexpr const auto name = "direction_flag";

        inline auto get() noexcept
        { return get_bit(__read_rflags(), from) != 0; }
    }

    namespace overflow_flag
    {
        constexpr const auto mask = 0x0000000000000800UL;
        constexpr const auto from = 11;
        constexpr const auto name = "overflow_flag";

        inline auto get() noexcept
        { return get_bit(__read_rflags(), from) != 0; }
    }

    namespace privilege_level
    {
        constexpr const auto mask = 0x0000000000003000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "privilege_level";

        inline auto get() noexcept
        { return get_bits(__read_rflags(), mask) >> from; }
    }

    namespace nested_task
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "nested_task";

        inline auto get() noexcept
        { return get_bit(__read_rflags(), from) != 0; }
    }

    namespace resume_flag
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "resume_flag";

        inline auto get() noexcept
        { return get_bit(__read_rflags(), from) != 0; }
    }

    namespace virtual_8086_mode
    {
        constexpr const auto mask = 0x0000000000020000UL;
        constexpr const auto from = 17;
        constexpr const auto name = "virtual_8086_mode";

        inline auto get() noexcept
        { return get_bit(__read_rflags(), from) != 0; }
    }

    namespace alignment_check_access_control
    {
        constexpr const auto mask = 0x0000000000040000UL;
        constexpr const auto from = 18;
        constexpr const auto name = "alignment_check_access_control";

        inline auto get() noexcept
        { return get_bit(__read_rflags(), from) != 0; }
    }

    namespace virtual_interupt_flag
    {
        constexpr const auto mask = 0x0000000000080000UL;
        constexpr const auto from = 19;
        constexpr const auto name = "virtual_interupt_flag";

        inline auto get() noexcept
        { return get_bit(__read_rflags(), from) != 0; }
    }

    namespace virtual_interupt_pending
    {
        constexpr const auto mask = 0x0000000000100000UL;
        constexpr const auto from = 20;
        constexpr const auto name = "virtual_interupt_pending";

        inline auto get() noexcept
        { return get_bit(__read_rflags(), from) != 0; }
    }

    namespace id_flag
    {
        constexpr const auto mask = 0x0000000000200000UL;
        constexpr const auto from = 21;
        constexpr const auto name = "id_flag";

        inline auto get() noexcept
        { return get_bit(__read_rflags(), from) != 0; }
    }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFC08028UL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get() noexcept
        { return get_bits(__read_rflags(), mask) >> from; }
    }

    namespace always_disabled
    {
        constexpr const auto mask = 0xFFFFFFFFFFC08028UL;
        constexpr const auto from = 0;
        constexpr const auto name = "always_disabled";

        inline auto get() noexcept
        { return get_bits(__read_rflags(), mask) >> from; }
    }

    namespace always_enabled
    {
        constexpr const auto mask = 0x0000000000000002UL;
        constexpr const auto from = 0;
        constexpr const auto name = "always_enabled";

        inline auto get() noexcept
        { return get_bits(__read_rflags(), mask) >> from; }
    }

    inline void dump() noexcept
    {
        bfdebug << "rflags enabled flags:" << bfendl;

        if (carry_flag::get())
            bfdebug << "    - " << carry_flag::name << bfendl;
        if (parity_flag::get())
            bfdebug << "    - " << parity_flag::name << bfendl;
        if (auxiliary_carry_flag::get())
            bfdebug << "    - " << auxiliary_carry_flag::name << bfendl;
        if (zero_flag::get())
            bfdebug << "    - " << zero_flag::name << bfendl;
        if (sign_flag::get())
            bfdebug << "    - " << sign_flag::name << bfendl;
        if (trap_flag::get())
            bfdebug << "    - " << trap_flag::name << bfendl;
        if (interrupt_enable_flag::get())
            bfdebug << "    - " << interrupt_enable_flag::name << bfendl;
        if (direction_flag::get())
            bfdebug << "    - " << direction_flag::name << bfendl;
        if (overflow_flag::get())
            bfdebug << "    - " << overflow_flag::name << bfendl;
        if (nested_task::get())
            bfdebug << "    - " << nested_task::name << bfendl;
        if (resume_flag::get())
            bfdebug << "    - " << resume_flag::name << bfendl;
        if (virtual_8086_mode::get())
            bfdebug << "    - " << virtual_8086_mode::name << bfendl;
        if (alignment_check_access_control::get())
            bfdebug << "    - " << alignment_check_access_control::name << bfendl;
        if (virtual_interupt_flag::get())
            bfdebug << "    - " << virtual_interupt_flag::name << bfendl;
        if (virtual_interupt_pending::get())
            bfdebug << "    - " << virtual_interupt_pending::name << bfendl;
        if (id_flag::get())
            bfdebug << "    - " << id_flag::name << bfendl;

        bfdebug << bfendl;
        bfdebug << "rflags fields:" << bfendl;

        bfdebug << "    - " << privilege_level::name << " = "
                << view_as_pointer(privilege_level::get()) << bfendl;
    }
}
}

// *INDENT-ON*

#endif
