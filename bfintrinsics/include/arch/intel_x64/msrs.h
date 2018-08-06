//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

#ifndef MSRS_INTEL_X64_H
#define MSRS_INTEL_X64_H

#include <arch/x64/msrs.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace msrs
{

using field_type = x64::msrs::field_type;
using value_type = x64::msrs::value_type;

inline auto get(field_type addr) noexcept
{ return _read_msr(addr); }

inline void set(field_type addr, value_type val) noexcept
{ _write_msr(addr, val); }

constexpr const field_type ia32_x2apic_beg = 0x00000800U;
constexpr const field_type ia32_x2apic_end = 0x00000BFFU;

namespace ia32_monitor_filter_size
{
    constexpr const auto addr = 0x00000006U;
    constexpr const auto name = "ia32_monitor_filter_size";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_platform_id
{
    constexpr const auto addr = 0x00000017U;
    constexpr const auto name = "ia32_platform_id";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace platform_id
    {
        constexpr const auto mask = 0x001C000000000000ULL;
        constexpr const auto from = 50ULL;
        constexpr const auto name = "platform_id";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        platform_id::dump(level, msg);
    }
}

namespace ia32_feature_control
{
    constexpr const auto addr = 0x0000003AU;
    constexpr const auto name = "ia32_feature_control";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace lock_bit
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "lock_bit";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace enable_vmx_inside_smx
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1ULL;
        constexpr const auto name = "enable_vmx_inside_smx";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace enable_vmx_outside_smx
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "enable_vmx_outside_smx";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace senter_local_function_enable
    {
        constexpr const auto mask = 0x0000000000007F00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "senter_local_function_enable";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace senter_global_function_enables
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15ULL;
        constexpr const auto name = "senter_global_function_enables";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace sgx_launch_control_enable
    {
        constexpr const auto mask = 0x0000000000020000ULL;
        constexpr const auto from = 17ULL;
        constexpr const auto name = "sgx_launch_control_enable";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace sgx_global_enable
    {
        constexpr const auto mask = 0x0000000000040000ULL;
        constexpr const auto from = 18ULL;
        constexpr const auto name = "sgx_global_enable";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace lmce
    {
        constexpr const auto mask = 0x0000000000100000ULL;
        constexpr const auto from = 20ULL;
        constexpr const auto name = "lmce";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        lock_bit::dump(level, msg);
        enable_vmx_inside_smx::dump(level, msg);
        enable_vmx_outside_smx::dump(level, msg);
        senter_local_function_enable::dump(level, msg);
        senter_global_function_enables::dump(level, msg);
        sgx_launch_control_enable::dump(level, msg);
        sgx_global_enable::dump(level, msg);
        lmce::dump(level, msg);
    }
}

namespace ia32_tsc_adjust
{
    constexpr const auto addr = 0x0000003BU;
    constexpr const auto name = "ia32_tsc_adjust";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace thread_adjust
    {
        constexpr const auto mask = 0xFFFFFFFFFFFFFFFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "thread_adjust";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        thread_adjust::dump(level, msg);
    }
}

namespace ia32_bios_updt_trig
{
    constexpr const auto addr = 0x00000079U;
    constexpr const auto name = "ia32_bios_updt_trig";

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }
}

namespace ia32_bios_sign_id
{
    constexpr const auto addr = 0x0000008BU;
    constexpr const auto name = "ia32_bios_sign_id";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace bios_sign_id
    {
        constexpr const auto mask = 0xFFFFFFFF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "bios_sign_id";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        bios_sign_id::dump(level, msg);
    }
}

namespace ia32_sgxlepubkeyhash0
{
    constexpr const auto addr = 0x0000008CU;
    constexpr const auto name = "ia32_sgxlepubkeyhash0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_sgxlepubkeyhash1
{
    constexpr const auto addr = 0x0000008DU;
    constexpr const auto name = "ia32_sgxlepubkeyhash1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_sgxlepubkeyhash2
{
    constexpr const auto addr = 0x0000008EU;
    constexpr const auto name = "ia32_sgxlepubkeyhash2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_sgxlepubkeyhash3
{
    constexpr const auto addr = 0x0000008FU;
    constexpr const auto name = "ia32_sgxlepubkeyhash3";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_smm_monitor_ctl
{
    constexpr const auto addr = 0x0000009BU;
    constexpr const auto name = "ia32_smm_monitor_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace valid
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "valid";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace vmxoff
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "vmxoff";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace mseg_base
    {
        constexpr const auto mask = 0x00000000FFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "mseg_base";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        valid::dump(level, msg);
        vmxoff::dump(level, msg);
        mseg_base::dump(level, msg);
    }
}

namespace ia32_smbase
{
    constexpr const auto addr = 0x0000009EU;
    constexpr const auto name = "ia32_smbase";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_pmc0
{
    constexpr const auto addr = 0x000000C1U;
    constexpr const auto name = "ia32_pmc0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_pmc1
{
    constexpr const auto addr = 0x000000C2U;
    constexpr const auto name = "ia32_pmc1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_pmc2
{
    constexpr const auto addr = 0x000000C3U;
    constexpr const auto name = "ia32_pmc2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_pmc3
{
    constexpr const auto addr = 0x000000C4U;
    constexpr const auto name = "ia32_pmc3";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_pmc4
{
    constexpr const auto addr = 0x000000C5U;
    constexpr const auto name = "ia32_pmc4";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_pmc5
{
    constexpr const auto addr = 0x000000C6U;
    constexpr const auto name = "ia32_pmc5";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_pmc6
{
    constexpr const auto addr = 0x000000C7U;
    constexpr const auto name = "ia32_pmc6";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_pmc7
{
    constexpr const auto addr = 0x000000C8U;
    constexpr const auto name = "ia32_pmc7";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_sysenter_cs
{
    constexpr const auto addr = 0x00000174U;
    constexpr const auto name = "ia32_sysenter_cs";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_sysenter_esp
{
    constexpr const auto addr = 0x00000175U;
    constexpr const auto name = "ia32_sysenter_esp";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_sysenter_eip
{
    constexpr const auto addr = 0x00000176;
    constexpr const auto name = "ia32_sysenter_eip";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_perfevtsel0
{
    constexpr const auto addr = 0x00000186;
    constexpr const auto name = "ia32_perfevtsel0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace event_select
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "event_select";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace umask
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "umask";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace usr
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "usr";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace os
    {
        constexpr const auto mask = 0x0000000000020000ULL;
        constexpr const auto from = 17ULL;
        constexpr const auto name = "os";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace edge
    {
        constexpr const auto mask = 0x0000000000040000ULL;
        constexpr const auto from = 18ULL;
        constexpr const auto name = "edge";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pc
    {
        constexpr const auto mask = 0x0000000000080000ULL;
        constexpr const auto from = 19ULL;
        constexpr const auto name = "pc";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace interrupt
    {
        constexpr const auto mask = 0x0000000000100000ULL;
        constexpr const auto from = 20ULL;
        constexpr const auto name = "interrupt";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace anythread
    {
        constexpr const auto mask = 0x0000000000200000ULL;
        constexpr const auto from = 21ULL;
        constexpr const auto name = "anythread";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace en
    {
        constexpr const auto mask = 0x0000000000400000ULL;
        constexpr const auto from = 22ULL;
        constexpr const auto name = "en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace inv
    {
        constexpr const auto mask = 0x0000000000800000ULL;
        constexpr const auto from = 23ULL;
        constexpr const auto name = "inv";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace cmask
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "cmask";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        event_select::dump(level, msg);
        umask::dump(level, msg);
        usr::dump(level, msg);
        os::dump(level, msg);
        edge::dump(level, msg);
        pc::dump(level, msg);
        interrupt::dump(level, msg);
        anythread::dump(level, msg);
        en::dump(level, msg);
        inv::dump(level, msg);
        cmask::dump(level, msg);
    }
}

namespace ia32_perfevtsel1
{
    constexpr const auto addr = 0x00000187;
    constexpr const auto name = "ia32_perfevtsel1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_perfevtsel2
{
    constexpr const auto addr = 0x00000188;
    constexpr const auto name = "ia32_perfevtsel2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_perfevtsel3
{
    constexpr const auto addr = 0x00000189;
    constexpr const auto name = "ia32_perfevtsel3";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_perf_status
{
    constexpr const auto addr = 0x00000198;
    constexpr const auto name = "ia32_perf_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace state_value
    {
        constexpr const auto mask = 0x000000000000FFFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "state_value";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        state_value::dump(level, msg);
    }
}

namespace ia32_perf_ctl
{
    constexpr const auto addr = 0x00000199;
    constexpr const auto name = "ia32_perf_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace state_value
    {
        constexpr const auto mask = 0x000000000000FFFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "state_value";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace ida_engage
    {
        constexpr const auto mask = 0x0000000100000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "ida_engage";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        state_value::dump(level, msg);
        ida_engage::dump(level, msg);
    }
}

namespace ia32_clock_modulation
{
    constexpr const auto addr = 0x0000019A;
    constexpr const auto name = "ia32_clock_modulation";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace ext_duty_cycle
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "ext_duty_cycle";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace duty_cycle_values
    {
        constexpr const auto mask = 0x000000000000000EULL;
        constexpr const auto from = 1ULL;
        constexpr const auto name = "duty_cycle_values";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace enable_modulation
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4ULL;
        constexpr const auto name = "enable_modulation";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        ext_duty_cycle::dump(level, msg);
        duty_cycle_values::dump(level, msg);
        enable_modulation::dump(level, msg);
    }
}

namespace ia32_therm_interrupt
{
    constexpr const auto addr = 0x0000019B;
    constexpr const auto name = "ia32_therm_interrupt";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace high_temp
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "high_temp";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace low_temp
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1ULL;
        constexpr const auto name = "low_temp";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace prochot
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "prochot";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace forcepr
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "forcepr";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace crit_temp
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4ULL;
        constexpr const auto name = "crit_temp";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace threshold_1_value
    {
        constexpr const auto mask = 0x0000000000007F00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "threshold_1_value";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace threshold_1_enable
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15ULL;
        constexpr const auto name = "threshold_1_enable";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace threshold_2_value
    {
        constexpr const auto mask = 0x00000000007F0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "threshold_2_value";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace threshold_2_enable
    {
        constexpr const auto mask = 0x0000000000800000ULL;
        constexpr const auto from = 23ULL;
        constexpr const auto name = "threshold_2_enable";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace power_limit
    {
        constexpr const auto mask = 0x0000000001000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "power_limit";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        high_temp::dump(level, msg);
        low_temp::dump(level, msg);
        prochot::dump(level, msg);
        forcepr::dump(level, msg);
        crit_temp::dump(level, msg);
        threshold_1_value::dump(level, msg);
        threshold_1_enable::dump(level, msg);
        threshold_2_value::dump(level, msg);
        threshold_2_enable::dump(level, msg);
        power_limit::dump(level, msg);
    }
}

namespace ia32_therm_status
{
    constexpr const auto addr = 0x0000019C;
    constexpr const auto name = "ia32_therm_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace therm_status
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "therm_status";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace thermal_status_log
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1ULL;
        constexpr const auto name = "thermal_status_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace forcepr_event
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "forcepr_event";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace forcepr_log
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "forcepr_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace crit_temp_status
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4ULL;
        constexpr const auto name = "crit_temp_status";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace crit_temp_log
    {
        constexpr const auto mask = 0x0000000000000020ULL;
        constexpr const auto from = 5ULL;
        constexpr const auto name = "crit_temp_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace therm_threshold1_status
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6ULL;
        constexpr const auto name = "therm_threshold1_status";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace therm_threshold1_log
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7ULL;
        constexpr const auto name = "therm_threshold1_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace therm_threshold2_status
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "therm_threshold2_status";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace therm_threshold2_log
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9ULL;
        constexpr const auto name = "therm_threshold2_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace power_limit_status
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "power_limit_status";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace power_limit_log
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "power_limit_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace current_limit_status
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "current_limit_status";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace current_limit_log
    {
        constexpr const auto mask = 0x0000000000002000ULL;
        constexpr const auto from = 13ULL;
        constexpr const auto name = "current_limit_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace cross_domain_status
    {
        constexpr const auto mask = 0x0000000000004000ULL;
        constexpr const auto from = 14ULL;
        constexpr const auto name = "cross_domain_status";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace cross_domain_log
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15ULL;
        constexpr const auto name = "cross_domain_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace digital_readout
    {
        constexpr const auto mask = 0x00000000007F0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "digital_readout";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace resolution_celcius
    {
        constexpr const auto mask = 0x0000000078000000ULL;
        constexpr const auto from = 27ULL;
        constexpr const auto name = "resolution_celcius";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace reading_valid
    {
        constexpr const auto mask = 0x0000000080000000ULL;
        constexpr const auto from = 31ULL;
        constexpr const auto name = "reading_valid";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        therm_status::dump(level, msg);
        thermal_status_log::dump(level, msg);
        forcepr_event::dump(level, msg);
        forcepr_log::dump(level, msg);
        crit_temp_status::dump(level, msg);
        crit_temp_log::dump(level, msg);
        therm_threshold1_status::dump(level, msg);
        therm_threshold1_log::dump(level, msg);
        therm_threshold2_status::dump(level, msg);
        therm_threshold2_log::dump(level, msg);
        power_limit_status::dump(level, msg);
        power_limit_log::dump(level, msg);
        current_limit_status::dump(level, msg);
        current_limit_log::dump(level, msg);
        cross_domain_status::dump(level, msg);
        cross_domain_log::dump(level, msg);
        digital_readout::dump(level, msg);
        resolution_celcius::dump(level, msg);
        reading_valid::dump(level, msg);
    }
}

namespace ia32_misc_enable
{
    constexpr const auto addr = 0x000001A0U;
    constexpr const auto name = "ia32_misc_enable";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace fast_strings
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "fast_strings";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace auto_therm_control
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "auto_therm_control";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace perf_monitor
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7ULL;
        constexpr const auto name = "perf_monitor";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace branch_trace_storage
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "branch_trace_storage";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace processor_sampling
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "processor_sampling";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace intel_speedstep
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "intel_speedstep";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace monitor_fsm
    {
        constexpr const auto mask = 0x0000000000040000ULL;
        constexpr const auto from = 18ULL;
        constexpr const auto name = "monitor_fsm";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace limit_cpuid_maxval
    {
        constexpr const auto mask = 0x0000000000400000ULL;
        constexpr const auto from = 22ULL;
        constexpr const auto name = "limit_cpuid_maxval";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace xtpr_message
    {
        constexpr const auto mask = 0x0000000000800000ULL;
        constexpr const auto from = 23ULL;
        constexpr const auto name = "xtpr_message";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace xd_bit
    {
        constexpr const auto mask = 0x0000000400000000ULL;
        constexpr const auto from = 34ULL;
        constexpr const auto name = "xd_bit";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        fast_strings::dump(level, msg);
        auto_therm_control::dump(level, msg);
        perf_monitor::dump(level, msg);
        branch_trace_storage::dump(level, msg);
        processor_sampling::dump(level, msg);
        intel_speedstep::dump(level, msg);
        monitor_fsm::dump(level, msg);
        limit_cpuid_maxval::dump(level, msg);
        xtpr_message::dump(level, msg);
        xd_bit::dump(level, msg);
    }
}

namespace ia32_energy_perf_bias
{
    constexpr const auto addr = 0x000001B0U;
    constexpr const auto name = "ia32_energy_perf_bias";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace power_policy
    {
        constexpr const auto mask = 0x000000000000000FULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "power_policy";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        power_policy::dump(level, msg);
    }
}

namespace ia32_package_therm_status
{
    constexpr const auto addr = 0x000001B1U;
    constexpr const auto name = "ia32_package_therm_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace pkg_therm_status
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "pkg_therm_status";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pkg_therm_log
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1ULL;
        constexpr const auto name = "pkg_therm_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pkg_prochot_event
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "pkg_prochot_event";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pkg_prochot_log
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "pkg_prochot_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pkg_crit_temp_status
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4ULL;
        constexpr const auto name = "pkg_crit_temp_status";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pkg_crit_temp_log
    {
        constexpr const auto mask = 0x0000000000000020ULL;
        constexpr const auto from = 5ULL;
        constexpr const auto name = "pkg_crit_temp_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pkg_therm_thresh1_status
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6ULL;
        constexpr const auto name = "pkg_therm_thresh1_status";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pkg_therm_thresh1_log
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7ULL;
        constexpr const auto name = "pkg_therm_thresh1_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pkg_therm_thresh2_status
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "pkg_therm_thresh2_status";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pkg_therm_thresh2_log
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9ULL;
        constexpr const auto name = "pkg_therm_thresh2_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pkg_power_limit_status
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "pkg_power_limit_status";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pkg_power_limit_log
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "pkg_power_limit_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pkg_digital_readout
    {
        constexpr const auto mask = 0x00000000007F0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "pkg_digital_readout";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        pkg_therm_status::dump(level, msg);
        pkg_therm_log::dump(level, msg);
        pkg_prochot_event::dump(level, msg);
        pkg_prochot_log::dump(level, msg);
        pkg_crit_temp_status::dump(level, msg);
        pkg_crit_temp_log::dump(level, msg);
        pkg_therm_thresh1_status::dump(level, msg);
        pkg_therm_thresh1_log::dump(level, msg);
        pkg_therm_thresh2_status::dump(level, msg);
        pkg_therm_thresh2_log::dump(level, msg);
        pkg_power_limit_status::dump(level, msg);
        pkg_power_limit_log::dump(level, msg);
        pkg_digital_readout::dump(level, msg);
    }
}

namespace ia32_package_therm_interrupt
{
    constexpr const auto addr = 0x000001B2U;
    constexpr const auto name = "ia32_energy_perf_bias";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace pkg_high_temp
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "pkg_high_temp";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pkg_low_temp
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1ULL;
        constexpr const auto name = "pkg_low_temp";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pkg_prochot
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "pkg_prochot";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pkg_overheat
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4ULL;
        constexpr const auto name = "pkg_overheat";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pkg_threshold_1_value
    {
        constexpr const auto mask = 0x0000000000007F00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "pkg_threshold_1_value";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace pkg_threshold_1_enable
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15ULL;
        constexpr const auto name = "pkg_threshold_1_enable";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pkg_threshold_2_value
    {
        constexpr const auto mask = 0x00000000007F0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "pkg_threshold_2_value";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace pkg_threshold_2_enable
    {
        constexpr const auto mask = 0x0000000000800000ULL;
        constexpr const auto from = 23ULL;
        constexpr const auto name = "pkg_threshold_2_enable";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pkg_power_limit
    {
        constexpr const auto mask = 0x0000000001000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "pkg_power_limit";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        pkg_high_temp::dump(level, msg);
        pkg_low_temp::dump(level, msg);
        pkg_prochot::dump(level, msg);
        pkg_overheat::dump(level, msg);
        pkg_threshold_1_value::dump(level, msg);
        pkg_threshold_1_enable::dump(level, msg);
        pkg_threshold_2_value::dump(level, msg);
        pkg_threshold_2_enable::dump(level, msg);
        pkg_power_limit::dump(level, msg);
    }
}

namespace ia32_debugctl
{
    constexpr const auto addr = 0x000001D9U;
    constexpr const auto name = "ia32_debugctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace lbr
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "lbr";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace btf
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1ULL;
        constexpr const auto name = "btf";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace tr
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6ULL;
        constexpr const auto name = "tr";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace bts
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7ULL;
        constexpr const auto name = "bts";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace btint
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "btint";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace bt_off_os
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9ULL;
        constexpr const auto name = "bt_off_os";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace bt_off_user
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "bt_off_user";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace freeze_lbrs_on_pmi
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "freeze_lbrs_on_pmi";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace freeze_perfmon_on_pmi
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "freeze_perfmon_on_pmi";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace enable_uncore_pmi
    {
        constexpr const auto mask = 0x0000000000002000ULL;
        constexpr const auto from = 13ULL;
        constexpr const auto name = "enable_uncore_pmi";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace freeze_while_smm
    {
        constexpr const auto mask = 0x0000000000004000ULL;
        constexpr const auto from = 14ULL;
        constexpr const auto name = "freeze_while_smm";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace rtm_debug
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15ULL;
        constexpr const auto name = "rtm_debug";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        lbr::dump(level, msg);
        btf::dump(level, msg);
        tr::dump(level, msg);
        bts::dump(level, msg);
        btint::dump(level, msg);
        bt_off_os::dump(level, msg);
        bt_off_user::dump(level, msg);
        freeze_lbrs_on_pmi::dump(level, msg);
        freeze_perfmon_on_pmi::dump(level, msg);
        enable_uncore_pmi::dump(level, msg);
        freeze_while_smm::dump(level, msg);
        rtm_debug::dump(level, msg);
    }
}

namespace ia32_smrr_physbase
{
    constexpr const auto addr = 0x000001F2U;
    constexpr const auto name = "ia32_smrr_physbase";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace type
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "type";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace physbase
    {
        constexpr const auto mask = 0x00000000FFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physbase";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        type::dump(level, msg);
        physbase::dump(level, msg);
    }
}

namespace ia32_smrr_physmask
{
    constexpr const auto addr = 0x000001F3U;
    constexpr const auto name = "ia32_smrr_physmask";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace valid
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "valid";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace physmask
    {
        constexpr const auto mask = 0x00000000FFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physmask";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        valid::dump(level, msg);
        physmask::dump(level, msg);
    }
}

namespace ia32_platform_dca_cap
{
    constexpr const auto addr = 0x000001F8U;
    constexpr const auto name = "ia32_platform_dca_cap";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_cpu_dca_cap
{
    constexpr const auto addr = 0x000001F9U;
    constexpr const auto name = "ia32_cpu_dca_cap";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_dca_0_cap
{
    constexpr const auto addr = 0x000001FAU;
    constexpr const auto name = "ia32_dca_0_cap";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace dca_active
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "dca_active";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace transaction
    {
        constexpr const auto mask = 0x0000000000000006ULL;
        constexpr const auto from = 1ULL;
        constexpr const auto name = "transaction";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace dca_type
    {
        constexpr const auto mask = 0x0000000000000078ULL;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "dca_type";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace dca_queue_size
    {
        constexpr const auto mask = 0x0000000000000780ULL;
        constexpr const auto from = 7ULL;
        constexpr const auto name = "dca_queue_size";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace dca_delay
    {
        constexpr const auto mask = 0x000000000001E000ULL;
        constexpr const auto from = 13ULL;
        constexpr const auto name = "dca_delay";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace sw_block
    {
        constexpr const auto mask = 0x0000000001000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "sw_block";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace hw_block
    {
        constexpr const auto mask = 0x0000000004000000ULL;
        constexpr const auto from = 26ULL;
        constexpr const auto name = "hw_block";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        dca_active::dump(level, msg);
        transaction::dump(level, msg);
        dca_type::dump(level, msg);
        dca_queue_size::dump(level, msg);
        dca_delay::dump(level, msg);
        sw_block::dump(level, msg);
        hw_block::dump(level, msg);
    }
}

namespace ia32_mtrr_physbase
{
    constexpr const auto addr = 0x00000200U;
    constexpr const auto name = "ia32_mtrr_physbase0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace type
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "type";

        constexpr const auto uncacheable = 0U;
        constexpr const auto write_combining = 1U;
        constexpr const auto write_through = 4U;
        constexpr const auto write_protected = 5U;
        constexpr const auto write_back = 6U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace physbase
    {
        constexpr const auto mask = 0x000FFFFFFFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physbase";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        type::dump(level, msg);
        physbase::dump(level, msg);
    }
}

namespace ia32_mtrr_physmask
{
    constexpr const auto addr = 0x00000201U;
    constexpr const auto name = "ia32_mtrr_physmask0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace valid
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "valid";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace physmask
    {
        constexpr const auto mask = 0x000FFFFFFFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physmask";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        valid::dump(level, msg);
        physmask::dump(level, msg);
    }
}

namespace ia32_mtrr_fix64k_00000
{
    constexpr const auto addr = 0x00000250U;
    constexpr const auto name = "ia32_mtrr_fix64k_00000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mtrr_fix16k_80000
{
    constexpr const auto addr = 0x00000258U;
    constexpr const auto name = "ia32_mtrr_fix16k_80000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mtrr_fix16k_A0000
{
    constexpr const auto addr = 0x00000259U;
    constexpr const auto name = "ia32_mtrr_fix16k_A0000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mtrr_fix4k_C0000
{
    constexpr const auto addr = 0x00000268U;
    constexpr const auto name = "ia32_mtrr_fix4k_C0000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mtrr_fix4k_C8000
{
    constexpr const auto addr = 0x00000269U;
    constexpr const auto name = "ia32_mtrr_fix4k_C8000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mtrr_fix4k_D0000
{
    constexpr const auto addr = 0x0000026AU;
    constexpr const auto name = "ia32_mtrr_fix4k_D0000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mtrr_fix4k_D8000
{
    constexpr const auto addr = 0x0000026BU;
    constexpr const auto name = "ia32_mtrr_fix4k_D8000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mtrr_fix4k_E0000
{
    constexpr const auto addr = 0x0000026CU;
    constexpr const auto name = "ia32_mtrr_fix4k_E0000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mtrr_fix4k_E8000
{
    constexpr const auto addr = 0x0000026DU;
    constexpr const auto name = "ia32_mtrr_fix4k_E8000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mtrr_fix4k_F0000
{
    constexpr const auto addr = 0x0000026EU;
    constexpr const auto name = "ia32_mtrr_fix4k_F0000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mtrr_fix4k_F8000
{
    constexpr const auto addr = 0x0000026FU;
    constexpr const auto name = "ia32_mtrr_fix4k_F8000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc0_ctl2
{
    constexpr const auto addr = 0x00000280U;
    constexpr const auto name = "ia32_mc0_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc1_ctl2
{
    constexpr const auto addr = 0x00000281U;
    constexpr const auto name = "ia32_mc1_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc2_ctl2
{
    constexpr const auto addr = 0x00000282U;
    constexpr const auto name = "ia32_mc2_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc3_ctl2
{
    constexpr const auto addr = 0x00000283U;
    constexpr const auto name = "ia32_mc3_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc4_ctl2
{
    constexpr const auto addr = 0x00000284U;
    constexpr const auto name = "ia32_mc4_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc5_ctl2
{
    constexpr const auto addr = 0x00000285U;
    constexpr const auto name = "ia32_mc5_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc6_ctl2
{
    constexpr const auto addr = 0x00000286U;
    constexpr const auto name = "ia32_mc6_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc7_ctl2
{
    constexpr const auto addr = 0x00000287U;
    constexpr const auto name = "ia32_mc7_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc8_ctl2
{
    constexpr const auto addr = 0x00000288U;
    constexpr const auto name = "ia32_mc8_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc9_ctl2
{
    constexpr const auto addr = 0x00000289U;
    constexpr const auto name = "ia32_mc9_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc10_ctl2
{
    constexpr const auto addr = 0x0000028AU;
    constexpr const auto name = "ia32_mc10_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc11_ctl2
{
    constexpr const auto addr = 0x0000028BU;
    constexpr const auto name = "ia32_mc11_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc12_ctl2
{
    constexpr const auto addr = 0x0000028CU;
    constexpr const auto name = "ia32_mc12_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc13_ctl2
{
    constexpr const auto addr = 0x0000028DU;
    constexpr const auto name = "ia32_mc13_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc14_ctl2
{
    constexpr const auto addr = 0x0000028EU;
    constexpr const auto name = "ia32_mc14_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc15_ctl2
{
    constexpr const auto addr = 0x0000028FU;
    constexpr const auto name = "ia32_mc15_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc16_ctl2
{
    constexpr const auto addr = 0x00000290U;
    constexpr const auto name = "ia32_mc16_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc17_ctl2
{
    constexpr const auto addr = 0x00000291U;
    constexpr const auto name = "ia32_mc17_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc18_ctl2
{
    constexpr const auto addr = 0x00000292U;
    constexpr const auto name = "ia32_mc18_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc19_ctl2
{
    constexpr const auto addr = 0x00000293U;
    constexpr const auto name = "ia32_mc19_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc20_ctl2
{
    constexpr const auto addr = 0x00000294U;
    constexpr const auto name = "ia32_mc20_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc21_ctl2
{
    constexpr const auto addr = 0x00000295U;
    constexpr const auto name = "ia32_mc21_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc22_ctl2
{
    constexpr const auto addr = 0x00000296U;
    constexpr const auto name = "ia32_mc22_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc23_ctl2
{
    constexpr const auto addr = 0x00000297U;
    constexpr const auto name = "ia32_mc23_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc24_ctl2
{
    constexpr const auto addr = 0x00000298U;
    constexpr const auto name = "ia32_mc24_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc25_ctl2
{
    constexpr const auto addr = 0x00000299U;
    constexpr const auto name = "ia32_mc25_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc26_ctl2
{
    constexpr const auto addr = 0x0000029AU;
    constexpr const auto name = "ia32_mc26_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc27_ctl2
{
    constexpr const auto addr = 0x0000029BU;
    constexpr const auto name = "ia32_mc27_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc28_ctl2
{
    constexpr const auto addr = 0x0000029CU;
    constexpr const auto name = "ia32_mc28_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc29_ctl2
{
    constexpr const auto addr = 0x0000029DU;
    constexpr const auto name = "ia32_mc29_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc30_ctl2
{
    constexpr const auto addr = 0x0000029EU;
    constexpr const auto name = "ia32_mc30_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mc31_ctl2
{
    constexpr const auto addr = 0x0000029FU;
    constexpr const auto name = "ia32_mc31_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        error_threshold::dump(level, msg);
        cmci_en::dump(level, msg);
    }
}

namespace ia32_mtrr_def_type
{
    constexpr const auto addr = 0x000002FFU;
    constexpr const auto name = "ia32_mtrr_def_type";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace type
    {
        constexpr const auto mask = 0x0000000000000007ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "type";

        constexpr const auto uncacheable = 0U;
        constexpr const auto write_combining = 1U;
        constexpr const auto write_through = 4U;
        constexpr const auto write_protected = 5U;
        constexpr const auto write_back = 6U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace fixed_range_mtrrs_enable
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "fixed_range_mtrr";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace mtrr_enable
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "mtrr";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        type::dump(level, msg);
        fixed_range_mtrrs_enable::dump(level, msg);
        mtrr_enable::dump(level, msg);
    }
}

namespace ia32_fixed_ctr0
{
    constexpr const auto addr = 0x00000309U;
    constexpr const auto name = "ia32_fixed_ctr0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_fixed_ctr1
{
    constexpr const auto addr = 0x0000030AU;
    constexpr const auto name = "ia32_fixed_ctr1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_fixed_ctr2
{
    constexpr const auto addr = 0x0000030BU;
    constexpr const auto name = "ia32_fixed_ctr2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_perf_capabilities
{
    constexpr const auto addr = 0x00000345U;
    constexpr const auto name = "ia32_perf_capabilities";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace lbo_format
    {
        constexpr const auto mask = 0x000000000000003FULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "lbo_format";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace pebs_trap
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6ULL;
        constexpr const auto name = "pebs_trap";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pebs_savearchregs
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7ULL;
        constexpr const auto name = "pebs_savearchregs";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pebs_record_format
    {
        constexpr const auto mask = 0x0000000000000F00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "pebs_record_format";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace freeze
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "freeze";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace counter_width
    {
        constexpr const auto mask = 0x0000000000002000ULL;
        constexpr const auto from = 13ULL;
        constexpr const auto name = "counter_width";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        lbo_format::dump(level, msg);
        pebs_trap::dump(level, msg);
        pebs_savearchregs::dump(level, msg);
        pebs_record_format::dump(level, msg);
        freeze::dump(level, msg);
        counter_width::dump(level, msg);
    }
}

namespace ia32_fixed_ctr_ctrl
{
    constexpr const auto addr = 0x0000038DU;
    constexpr const auto name = "ia32_fixed_ctr_ctrl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace en0_os
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "en0_os";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace en0_usr
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1ULL;
        constexpr const auto name = "en0_usr";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace en0_anythread
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "en0_anythread";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace en0_pmi
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "en0_pmi";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace en1_os
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4ULL;
        constexpr const auto name = "en1_os";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace en1_usr
    {
        constexpr const auto mask = 0x0000000000000020ULL;
        constexpr const auto from = 5ULL;
        constexpr const auto name = "en1_usr";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace en1_anythread
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6ULL;
        constexpr const auto name = "en1_anythread";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace en1_pmi
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7ULL;
        constexpr const auto name = "en1_pmi";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace en2_os
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "en2_os";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace en2_usr
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9ULL;
        constexpr const auto name = "en2_usr";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace en2_anythread
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "en2_anythread";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace en2_pmi
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "en2_pmi";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        en0_os::dump(level, msg);
        en0_usr::dump(level, msg);
        en0_anythread::dump(level, msg);
        en0_pmi::dump(level, msg);
        en1_os::dump(level, msg);
        en1_usr::dump(level, msg);
        en1_anythread::dump(level, msg);
        en1_pmi::dump(level, msg);
        en2_os::dump(level, msg);
        en2_usr::dump(level, msg);
        en2_anythread::dump(level, msg);
        en2_pmi::dump(level, msg);
    }
}

namespace ia32_perf_global_status
{
    constexpr const auto addr = 0x0000038EU;
    constexpr const auto name = "ia32_perf_global_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace ovf_pmc0
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "ovf_pmc0";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace ovf_pmc1
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1ULL;
        constexpr const auto name = "ovf_pmc1";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace ovf_pmc2
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "ovf_pmc2";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace ovf_pmc3
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "ovf_pmc3";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace ovf_fixedctr0
    {
        constexpr const auto mask = 0x0000000100000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "ovf_fixedctr0";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace ovf_fixedctr1
    {
        constexpr const auto mask = 0x0000000200000000ULL;
        constexpr const auto from = 33ULL;
        constexpr const auto name = "ovf_fixedctr1";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace ovf_fixedctr2
    {
        constexpr const auto mask = 0x0000000400000000ULL;
        constexpr const auto from = 34ULL;
        constexpr const auto name = "ovf_fixedctr2";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace trace_topa_pmi
    {
        constexpr const auto mask = 0x0080000000000000ULL;
        constexpr const auto from = 55ULL;
        constexpr const auto name = "trace_topa_pmi";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace lbr_frz
    {
        constexpr const auto mask = 0x0400000000000000ULL;
        constexpr const auto from = 58ULL;
        constexpr const auto name = "lbr_frz";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace ctr_frz
    {
        constexpr const auto mask = 0x0800000000000000ULL;
        constexpr const auto from = 59ULL;
        constexpr const auto name = "ctr_frz";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace asci
    {
        constexpr const auto mask = 0x1000000000000000ULL;
        constexpr const auto from = 60ULL;
        constexpr const auto name = "asci";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace ovf_uncore
    {
        constexpr const auto mask = 0x2000000000000000ULL;
        constexpr const auto from = 61ULL;
        constexpr const auto name = "ovf_uncore";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace ovfbuf
    {
        constexpr const auto mask = 0x4000000000000000ULL;
        constexpr const auto from = 62ULL;
        constexpr const auto name = "ovfbuf";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace condchgd
    {
        constexpr const auto mask = 0x8000000000000000ULL;
        constexpr const auto from = 63ULL;
        constexpr const auto name = "condchgd";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        ovf_pmc0::dump(level, msg);
        ovf_pmc1::dump(level, msg);
        ovf_pmc2::dump(level, msg);
        ovf_pmc3::dump(level, msg);
        ovf_fixedctr0::dump(level, msg);
        ovf_fixedctr1::dump(level, msg);
        ovf_fixedctr2::dump(level, msg);
        trace_topa_pmi::dump(level, msg);
        lbr_frz::dump(level, msg);
        ctr_frz::dump(level, msg);
        asci::dump(level, msg);
        ovf_uncore::dump(level, msg);
        ovfbuf::dump(level, msg);
        condchgd::dump(level, msg);
    }
}

namespace ia32_perf_global_ctrl
{
    constexpr const auto addr = 0x0000038FU;
    constexpr const auto name = "ia32_perf_global_ctrl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace pmc0
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "pmc0";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pmc1
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1ULL;
        constexpr const auto name = "pmc1";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pmc2
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "pmc2";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pmc3
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "pmc3";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pmc4
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4ULL;
        constexpr const auto name = "pmc4";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pmc5
    {
        constexpr const auto mask = 0x0000000000000020ULL;
        constexpr const auto from = 5ULL;
        constexpr const auto name = "pmc5";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pmc6
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6ULL;
        constexpr const auto name = "pmc6";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pmc7
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7ULL;
        constexpr const auto name = "pmc7";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace fixed_ctr0
    {
        constexpr const auto mask = 0x0000000100000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "fixed_ctr0";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace fixed_ctr1
    {
        constexpr const auto mask = 0x0000000200000000ULL;
        constexpr const auto from = 33ULL;
        constexpr const auto name = "fixed_ctr1";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace fixed_ctr2
    {
        constexpr const auto mask = 0x0000000400000000ULL;
        constexpr const auto from = 34ULL;
        constexpr const auto name = "fixed_ctr2";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        pmc0::dump(level, msg);
        pmc1::dump(level, msg);
        pmc2::dump(level, msg);
        pmc3::dump(level, msg);
        pmc4::dump(level, msg);
        pmc5::dump(level, msg);
        pmc6::dump(level, msg);
        pmc7::dump(level, msg);
        fixed_ctr0::dump(level, msg);
        fixed_ctr1::dump(level, msg);
        fixed_ctr2::dump(level, msg);
    }
}

namespace ia32_perf_global_ovf_ctrl
{
    constexpr const auto addr = 0x00000390U;
    constexpr const auto name = "ia32_perf_global_ovf_ctrl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace clear_ovf_pmc0
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "clear_ovf_pmc0";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace clear_ovf_pmc1
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1ULL;
        constexpr const auto name = "clear_ovf_pmc1";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace clear_ovf_pmc2
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "clear_ovf_pmc2";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace clear_ovf_fixed_ctr0
    {
        constexpr const auto mask = 0x0000000100000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "clear_ovf_fixed_ctr0";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace clear_ovf_fixed_ctr1
    {
        constexpr const auto mask = 0x0000000200000000ULL;
        constexpr const auto from = 33ULL;
        constexpr const auto name = "clear_ovf_fixed_ctr1";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace clear_ovf_fixed_ctr2
    {
        constexpr const auto mask = 0x0000000400000000ULL;
        constexpr const auto from = 34ULL;
        constexpr const auto name = "clear_ovf_fixed_ctr2";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace clear_trace_topa_pmi
    {
        constexpr const auto mask = 0x0080000000000000ULL;
        constexpr const auto from = 55ULL;
        constexpr const auto name = "clear_trace_topa_pmi";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace lbr_frz
    {
        constexpr const auto mask = 0x0400000000000000ULL;
        constexpr const auto from = 58ULL;
        constexpr const auto name = "lbr_frz";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace ctr_frz
    {
        constexpr const auto mask = 0x0800000000000000ULL;
        constexpr const auto from = 59ULL;
        constexpr const auto name = "ctr_frz";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace clear_ovf_uncore
    {
        constexpr const auto mask = 0x2000000000000000ULL;
        constexpr const auto from = 61ULL;
        constexpr const auto name = "clear_ovf_uncore";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace clear_ovfbuf
    {
        constexpr const auto mask = 0x4000000000000000ULL;
        constexpr const auto from = 62ULL;
        constexpr const auto name = "clear_ovfbuf";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace clear_condchgd
    {
        constexpr const auto mask = 0x8000000000000000ULL;
        constexpr const auto from = 63ULL;
        constexpr const auto name = "clear_condchgd";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        clear_ovf_pmc0::dump(level, msg);
        clear_ovf_pmc1::dump(level, msg);
        clear_ovf_pmc2::dump(level, msg);
        clear_ovf_fixed_ctr0::dump(level, msg);
        clear_ovf_fixed_ctr1::dump(level, msg);
        clear_ovf_fixed_ctr2::dump(level, msg);
        clear_trace_topa_pmi::dump(level, msg);
        lbr_frz::dump(level, msg);
        ctr_frz::dump(level, msg);
        clear_ovf_uncore::dump(level, msg);
        clear_ovfbuf::dump(level, msg);
        clear_condchgd::dump(level, msg);
    }
}

namespace ia32_perf_global_status_set
{
    constexpr const auto addr = 0x00000391U;
    constexpr const auto name = "ia32_perf_global_status_set";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace ovf_pmc0
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "ovf_pmc0";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace ovf_pmc1
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1ULL;
        constexpr const auto name = "ovf_pmc1";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace ovf_pmc2
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "ovf_pmc2";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace ovf_fixed_ctr0
    {
        constexpr const auto mask = 0x0000000100000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "ovf_fixed_ctr0";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace ovf_fixed_ctr1
    {
        constexpr const auto mask = 0x0000000200000000ULL;
        constexpr const auto from = 33ULL;
        constexpr const auto name = "ovf_fixed_ctr1";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace ovf_fixed_ctr2
    {
        constexpr const auto mask = 0x0000000400000000ULL;
        constexpr const auto from = 34ULL;
        constexpr const auto name = "ovf_fixed_ctr2";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace trace_topa_pmi
    {
        constexpr const auto mask = 0x0080000000000000ULL;
        constexpr const auto from = 55ULL;
        constexpr const auto name = "trace_topa_pmi";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace lbr_frz
    {
        constexpr const auto mask = 0x0400000000000000ULL;
        constexpr const auto from = 58ULL;
        constexpr const auto name = "lbr_frz";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace ctr_frz
    {
        constexpr const auto mask = 0x0800000000000000ULL;
        constexpr const auto from = 59ULL;
        constexpr const auto name = "ctr_frz";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace ovf_uncore
    {
        constexpr const auto mask = 0x2000000000000000ULL;
        constexpr const auto from = 61ULL;
        constexpr const auto name = "ovf_uncore";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace ovfbuf
    {
        constexpr const auto mask = 0x4000000000000000ULL;
        constexpr const auto from = 62ULL;
        constexpr const auto name = "clear_ovfbuf";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        ovf_pmc0::dump(level, msg);
        ovf_pmc1::dump(level, msg);
        ovf_pmc2::dump(level, msg);
        ovf_fixed_ctr0::dump(level, msg);
        ovf_fixed_ctr1::dump(level, msg);
        ovf_fixed_ctr2::dump(level, msg);
        trace_topa_pmi::dump(level, msg);
        lbr_frz::dump(level, msg);
        ctr_frz::dump(level, msg);
        ovf_uncore::dump(level, msg);
        ovfbuf::dump(level, msg);
    }
}

namespace ia32_perf_global_inuse
{
    constexpr const auto addr = 0x00000392U;
    constexpr const auto name = "ia32_perf_global_inuse";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace perfevtsel0
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "perfevtsel0";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace perfevtsel1
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1ULL;
        constexpr const auto name = "perfevtsel1";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace perfevtsel2
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "perfevtsel2";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace fixed_ctr0
    {
        constexpr const auto mask = 0x0000000100000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "fixed_ctr0";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace fixed_ctr1
    {
        constexpr const auto mask = 0x0000000200000000ULL;
        constexpr const auto from = 33ULL;
        constexpr const auto name = "fixed_ctr1";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace fixed_ctr2
    {
        constexpr const auto mask = 0x0000000400000000ULL;
        constexpr const auto from = 34ULL;
        constexpr const auto name = "fixed_ctr2";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pmi
    {
        constexpr const auto mask = 0x8000000000000000ULL;
        constexpr const auto from = 63ULL;
        constexpr const auto name = "pmi";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        perfevtsel0::dump(level, msg);
        perfevtsel1::dump(level, msg);
        perfevtsel2::dump(level, msg);
        fixed_ctr0::dump(level, msg);
        fixed_ctr1::dump(level, msg);
        fixed_ctr2::dump(level, msg);
        pmi::dump(level, msg);
    }
}

namespace ia32_pebs_enable
{
    constexpr const auto addr = 0x000003F1U;
    constexpr const auto name = "ia32_pebs_enable";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace pebs
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "pebs";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        pebs::dump(level, msg);
    }
}

namespace ia32_mc6_ctl
{
    constexpr const auto addr = 0x00000418U;
    constexpr const auto name = "ia32_mc6_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc6_status
{
    constexpr const auto addr = 0x00000419U;
    constexpr const auto name = "ia32_mc6_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc6_addr
{
    constexpr const auto addr = 0x0000041AU;
    constexpr const auto name = "ia32_mc6_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc6_misc
{
    constexpr const auto addr = 0x0000041BU;
    constexpr const auto name = "ia32_mc6_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc7_ctl
{
    constexpr const auto addr = 0x0000041CU;
    constexpr const auto name = "ia32_mc7_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc7_status
{
    constexpr const auto addr = 0x0000041DU;
    constexpr const auto name = "ia32_mc7_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc7_addr
{
    constexpr const auto addr = 0x0000041EU;
    constexpr const auto name = "ia32_mc7_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc7_misc
{
    constexpr const auto addr = 0x0000041FU;
    constexpr const auto name = "ia32_mc7_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc8_ctl
{
    constexpr const auto addr = 0x00000420U;
    constexpr const auto name = "ia32_mc8_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc8_status
{
    constexpr const auto addr = 0x00000421U;
    constexpr const auto name = "ia32_mc8_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc8_addr
{
    constexpr const auto addr = 0x00000422U;
    constexpr const auto name = "ia32_mc8_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc8_misc
{
    constexpr const auto addr = 0x00000423U;
    constexpr const auto name = "ia32_mc8_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc9_ctl
{
    constexpr const auto addr = 0x00000424U;
    constexpr const auto name = "ia32_mc9_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc9_status
{
    constexpr const auto addr = 0x00000425U;
    constexpr const auto name = "ia32_mc9_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc9_addr
{
    constexpr const auto addr = 0x00000426U;
    constexpr const auto name = "ia32_mc9_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc9_misc
{
    constexpr const auto addr = 0x00000427U;
    constexpr const auto name = "ia32_mc9_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc10_ctl
{
    constexpr const auto addr = 0x00000428U;
    constexpr const auto name = "ia32_mc10_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc10_status
{
    constexpr const auto addr = 0x00000429U;
    constexpr const auto name = "ia32_mc10_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc10_addr
{
    constexpr const auto addr = 0x0000042AU;
    constexpr const auto name = "ia32_mc10_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc10_misc
{
    constexpr const auto addr = 0x0000042BU;
    constexpr const auto name = "ia32_mc10_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc11_ctl
{
    constexpr const auto addr = 0x0000042CU;
    constexpr const auto name = "ia32_mc11_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc11_status
{
    constexpr const auto addr = 0x0000042DU;
    constexpr const auto name = "ia32_mc11_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc11_addr
{
    constexpr const auto addr = 0x0000042EU;
    constexpr const auto name = "ia32_mc11_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc11_misc
{
    constexpr const auto addr = 0x0000042FU;
    constexpr const auto name = "ia32_mc11_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc12_ctl
{
    constexpr const auto addr = 0x00000430U;
    constexpr const auto name = "ia32_mc12_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc12_status
{
    constexpr const auto addr = 0x00000431U;
    constexpr const auto name = "ia32_mc12_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc12_addr
{
    constexpr const auto addr = 0x00000432U;
    constexpr const auto name = "ia32_mc12_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc12_misc
{
    constexpr const auto addr = 0x00000433U;
    constexpr const auto name = "ia32_mc12_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc13_ctl
{
    constexpr const auto addr = 0x00000434U;
    constexpr const auto name = "ia32_mc13_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc13_status
{
    constexpr const auto addr = 0x00000435U;
    constexpr const auto name = "ia32_mc13_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc13_addr
{
    constexpr const auto addr = 0x00000436U;
    constexpr const auto name = "ia32_mc13_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc13_misc
{
    constexpr const auto addr = 0x00000437U;
    constexpr const auto name = "ia32_mc13_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc14_ctl
{
    constexpr const auto addr = 0x00000438U;
    constexpr const auto name = "ia32_mc14_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc14_status
{
    constexpr const auto addr = 0x00000439U;
    constexpr const auto name = "ia32_mc14_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc14_addr
{
    constexpr const auto addr = 0x0000043AU;
    constexpr const auto name = "ia32_mc14_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc14_misc
{
    constexpr const auto addr = 0x0000043BU;
    constexpr const auto name = "ia32_mc14_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc15_ctl
{
    constexpr const auto addr = 0x0000043CU;
    constexpr const auto name = "ia32_mc15_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc15_status
{
    constexpr const auto addr = 0x0000043DU;
    constexpr const auto name = "ia32_mc15_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc15_addr
{
    constexpr const auto addr = 0x0000043EU;
    constexpr const auto name = "ia32_mc15_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc15_misc
{
    constexpr const auto addr = 0x0000043FU;
    constexpr const auto name = "ia32_mc15_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc16_ctl
{
    constexpr const auto addr = 0x00000440U;
    constexpr const auto name = "ia32_mc16_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc16_status
{
    constexpr const auto addr = 0x00000441U;
    constexpr const auto name = "ia32_mc16_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc16_addr
{
    constexpr const auto addr = 0x00000442U;
    constexpr const auto name = "ia32_mc16_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc16_misc
{
    constexpr const auto addr = 0x00000443U;
    constexpr const auto name = "ia32_mc16_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc17_ctl
{
    constexpr const auto addr = 0x00000444U;
    constexpr const auto name = "ia32_mc17_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc17_status
{
    constexpr const auto addr = 0x00000445U;
    constexpr const auto name = "ia32_mc17_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc17_addr
{
    constexpr const auto addr = 0x00000446U;
    constexpr const auto name = "ia32_mc17_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc17_misc
{
    constexpr const auto addr = 0x00000447U;
    constexpr const auto name = "ia32_mc17_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc18_ctl
{
    constexpr const auto addr = 0x00000448U;
    constexpr const auto name = "ia32_mc18_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc18_status
{
    constexpr const auto addr = 0x00000449U;
    constexpr const auto name = "ia32_mc18_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc18_addr
{
    constexpr const auto addr = 0x0000044AU;
    constexpr const auto name = "ia32_mc18_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc18_misc
{
    constexpr const auto addr = 0x0000044BU;
    constexpr const auto name = "ia32_mc18_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc19_ctl
{
    constexpr const auto addr = 0x0000044CU;
    constexpr const auto name = "ia32_mc19_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc19_status
{
    constexpr const auto addr = 0x0000044DU;
    constexpr const auto name = "ia32_mc19_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc19_addr
{
    constexpr const auto addr = 0x0000044EU;
    constexpr const auto name = "ia32_mc19_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc19_misc
{
    constexpr const auto addr = 0x0000044FU;
    constexpr const auto name = "ia32_mc19_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc20_ctl
{
    constexpr const auto addr = 0x00000450U;
    constexpr const auto name = "ia32_mc20_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc20_status
{
    constexpr const auto addr = 0x00000451U;
    constexpr const auto name = "ia32_mc20_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc20_addr
{
    constexpr const auto addr = 0x00000452U;
    constexpr const auto name = "ia32_mc20_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc20_misc
{
    constexpr const auto addr = 0x00000453U;
    constexpr const auto name = "ia32_mc20_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc21_ctl
{
    constexpr const auto addr = 0x00000454U;
    constexpr const auto name = "ia32_mc21_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc21_status
{
    constexpr const auto addr = 0x00000455U;
    constexpr const auto name = "ia32_mc21_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc21_addr
{
    constexpr const auto addr = 0x00000456U;
    constexpr const auto name = "ia32_mc21_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc21_misc
{
    constexpr const auto addr = 0x00000457U;
    constexpr const auto name = "ia32_mc21_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc22_ctl
{
    constexpr const auto addr = 0x00000458U;
    constexpr const auto name = "ia32_mc22_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc22_status
{
    constexpr const auto addr = 0x00000459U;
    constexpr const auto name = "ia32_mc22_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc22_addr
{
    constexpr const auto addr = 0x0000045AU;
    constexpr const auto name = "ia32_mc22_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc22_misc
{
    constexpr const auto addr = 0x0000045BU;
    constexpr const auto name = "ia32_mc22_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc23_ctl
{
    constexpr const auto addr = 0x0000045CU;
    constexpr const auto name = "ia32_mc23_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc23_status
{
    constexpr const auto addr = 0x0000045DU;
    constexpr const auto name = "ia32_mc23_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc23_addr
{
    constexpr const auto addr = 0x0000045EU;
    constexpr const auto name = "ia32_mc23_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc23_misc
{
    constexpr const auto addr = 0x0000045FU;
    constexpr const auto name = "ia32_mc23_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc24_ctl
{
    constexpr const auto addr = 0x00000460U;
    constexpr const auto name = "ia32_mc24_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc24_status
{
    constexpr const auto addr = 0x00000461U;
    constexpr const auto name = "ia32_mc24_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc24_addr
{
    constexpr const auto addr = 0x00000462U;
    constexpr const auto name = "ia32_mc24_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc24_misc
{
    constexpr const auto addr = 0x00000463U;
    constexpr const auto name = "ia32_mc24_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc25_ctl
{
    constexpr const auto addr = 0x00000464U;
    constexpr const auto name = "ia32_mc25_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc25_status
{
    constexpr const auto addr = 0x00000465U;
    constexpr const auto name = "ia32_mc25_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc25_addr
{
    constexpr const auto addr = 0x00000466U;
    constexpr const auto name = "ia32_mc25_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc25_misc
{
    constexpr const auto addr = 0x00000467U;
    constexpr const auto name = "ia32_mc25_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc26_ctl
{
    constexpr const auto addr = 0x00000468U;
    constexpr const auto name = "ia32_mc26_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc26_status
{
    constexpr const auto addr = 0x00000469U;
    constexpr const auto name = "ia32_mc26_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc26_addr
{
    constexpr const auto addr = 0x0000046AU;
    constexpr const auto name = "ia32_mc26_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc26_misc
{
    constexpr const auto addr = 0x0000046BU;
    constexpr const auto name = "ia32_mc26_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc27_ctl
{
    constexpr const auto addr = 0x0000046CU;
    constexpr const auto name = "ia32_mc27_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc27_status
{
    constexpr const auto addr = 0x0000046DU;
    constexpr const auto name = "ia32_mc27_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc27_addr
{
    constexpr const auto addr = 0x0000046EU;
    constexpr const auto name = "ia32_mc27_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc27_misc
{
    constexpr const auto addr = 0x0000046FU;
    constexpr const auto name = "ia32_mc27_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc28_ctl
{
    constexpr const auto addr = 0x00000470U;
    constexpr const auto name = "ia32_mc28_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc28_status
{
    constexpr const auto addr = 0x00000471U;
    constexpr const auto name = "ia32_mc28_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc28_addr
{
    constexpr const auto addr = 0x00000472U;
    constexpr const auto name = "ia32_mc28_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc28_misc
{
    constexpr const auto addr = 0x00000473U;
    constexpr const auto name = "ia32_mc28_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_vmx_basic
{
    constexpr const auto addr = 0x00000480U;
    constexpr const auto name = "ia32_vmx_basic";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace revision_id
    {
        constexpr const auto mask = 0x000000007FFFFFFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "revision_id";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace vmxon_vmcs_region_size
    {
        constexpr const auto mask = 0x00001FFF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "vmxon_vmcs_region_size";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace physical_address_width
    {
        constexpr const auto mask = 0x0001000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "physical_address_width";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace dual_monitor_mode_support
    {
        constexpr const auto mask = 0x0002000000000000ULL;
        constexpr const auto from = 49ULL;
        constexpr const auto name = "dual_monitor_mode_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace memory_type
    {
        constexpr const auto mask = 0x003C000000000000ULL;
        constexpr const auto from = 50ULL;
        constexpr const auto name = "memory_type";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace ins_outs_exit_information
    {
        constexpr const auto mask = 0x0040000000000000ULL;
        constexpr const auto from = 54ULL;
        constexpr const auto name = "ins_outs_exit_information";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace true_based_controls
    {
        constexpr const auto mask = 0x0080000000000000ULL;
        constexpr const auto from = 55ULL;
        constexpr const auto name = "true_based_controls";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        revision_id::dump(level, msg);
        vmxon_vmcs_region_size::dump(level, msg);
        physical_address_width::dump(level, msg);
        dual_monitor_mode_support::dump(level, msg);
        memory_type::dump(level, msg);
        ins_outs_exit_information::dump(level, msg);
        true_based_controls::dump(level, msg);
    }
}

namespace ia32_vmx_pinbased_ctls
{
    constexpr const auto addr = 0x00000481U;
    constexpr const auto name = "ia32_vmx_pinbased_ctls";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace allowed_0_settings
    {
        constexpr const auto mask = 0x00000000FFFFFFFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "allowed_0_settings";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace allowed_1_settings
    {
        constexpr const auto mask = 0xFFFFFFFF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "allowed_1_settings";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        allowed_0_settings::dump(level, msg);
        allowed_1_settings::dump(level, msg);
    }
}

namespace ia32_vmx_procbased_ctls
{
    constexpr const auto addr = 0x00000482U;
    constexpr const auto name = "ia32_vmx_procbased_ctls";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace allowed_0_settings
    {
        constexpr const auto mask = 0x00000000FFFFFFFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "allowed_0_settings";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace allowed_1_settings
    {
        constexpr const auto mask = 0xFFFFFFFF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "allowed_1_settings";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        allowed_0_settings::dump(level, msg);
        allowed_1_settings::dump(level, msg);
    }
}

namespace ia32_vmx_exit_ctls
{
    constexpr const auto addr = 0x00000483U;
    constexpr const auto name = "ia32_vmx_exit_ctls";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace allowed_0_settings
    {
        constexpr const auto mask = 0x00000000FFFFFFFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "allowed_0_settings";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace allowed_1_settings
    {
        constexpr const auto mask = 0xFFFFFFFF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "allowed_1_settings";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        allowed_0_settings::dump(level, msg);
        allowed_1_settings::dump(level, msg);
    }
}

namespace ia32_vmx_entry_ctls
{
    constexpr const auto addr = 0x00000484U;
    constexpr const auto name = "ia32_vmx_entry_ctls";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace allowed_0_settings
    {
        constexpr const auto mask = 0x00000000FFFFFFFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "allowed_0_settings";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace allowed_1_settings
    {
        constexpr const auto mask = 0xFFFFFFFF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "allowed_1_settings";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        allowed_0_settings::dump(level, msg);
        allowed_1_settings::dump(level, msg);
    }
}

namespace ia32_vmx_misc
{
    constexpr const auto addr = 0x00000485U;
    constexpr const auto name = "ia32_vmx_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace preemption_timer_decrement
    {
        constexpr const auto mask = 0x000000000000001FULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "preemption_timer_decrement";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace store_efer_lma_on_vm_exit
    {
        constexpr const auto mask = 0x0000000000000020ULL;
        constexpr const auto from = 5ULL;
        constexpr const auto name = "store_efer_lma_on_vm_exit";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace activity_state_hlt_support
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6ULL;
        constexpr const auto name = "activity_state_hlt_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace activity_state_shutdown_support
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7ULL;
        constexpr const auto name = "activity_state_shutdown_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace activity_state_wait_for_sipi_support
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "activity_state_wait_for_sipi_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace processor_trace_support
    {
        constexpr const auto mask = 0x0000000000004000ULL;
        constexpr const auto from = 14ULL;
        constexpr const auto name = "processor_trace_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace rdmsr_in_smm_support
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15ULL;
        constexpr const auto name = "rdmsr_in_smm_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace cr3_targets
    {
        constexpr const auto mask = 0x0000000001FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "cr3_targets";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace max_num_msr_load_store_on_exit
    {
        constexpr const auto mask = 0x000000000E000000ULL;
        constexpr const auto from = 25ULL;
        constexpr const auto name = "max_num_msr_load_store_on_exit";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace vmxoff_blocked_smi_support
    {
        constexpr const auto mask = 0x0000000010000000ULL;
        constexpr const auto from = 28ULL;
        constexpr const auto name = "vmxoff_blocked_smi_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace vmwrite_all_fields_support
    {
        constexpr const auto mask = 0x0000000020000000ULL;
        constexpr const auto from = 29ULL;
        constexpr const auto name = "vmwrite_all_fields_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace injection_with_instruction_length_of_zero
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "injection_with_instruction_length_of_zero";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        preemption_timer_decrement::dump(level, msg);
        store_efer_lma_on_vm_exit::dump(level, msg);
        activity_state_hlt_support::dump(level, msg);
        activity_state_shutdown_support::dump(level, msg);
        activity_state_wait_for_sipi_support::dump(level, msg);
        processor_trace_support::dump(level, msg);
        rdmsr_in_smm_support::dump(level, msg);
        cr3_targets::dump(level, msg);
        max_num_msr_load_store_on_exit::dump(level, msg);
        vmxoff_blocked_smi_support::dump(level, msg);
        vmwrite_all_fields_support::dump(level, msg);
        injection_with_instruction_length_of_zero::dump(level, msg);
    }
}

namespace ia32_vmx_cr0_fixed0
{
    constexpr const auto addr = 0x00000486U;
    constexpr const auto name = "ia32_vmx_cr0_fixed0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_vmx_cr0_fixed1
{
    constexpr const auto addr = 0x00000487U;
    constexpr const auto name = "ia32_vmx_cr0_fixed1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_vmx_cr4_fixed0
{
    constexpr const auto addr = 0x00000488U;
    constexpr const auto name = "ia32_vmx_cr4_fixed0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_vmx_cr4_fixed1
{
    constexpr const auto addr = 0x00000489U;
    constexpr const auto name = "ia32_vmx_cr4_fixed1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_vmx_vmcs_enum
{
    constexpr const auto addr = 0x0000048AU;
    constexpr const auto name = "ia32_vmx_vmcs_enum";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace highest_index
    {
        constexpr const auto mask = 0x00000000000003FEULL;
        constexpr const auto from = 1ULL;
        constexpr const auto name = "highest_index";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        highest_index::dump(level, msg);
    }
}

namespace ia32_vmx_procbased_ctls2
{
    constexpr const auto addr = 0x0000048BU;
    constexpr const auto name = "ia32_vmx_procbased_ctls2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto allowed0()
    { return (_read_msr(addr) & 0x00000000FFFFFFFFULL); }

    inline auto allowed1()
    { return ((_read_msr(addr) & 0xFFFFFFFF00000000ULL) >> 32); }

    namespace virtualize_apic_accesses
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "virtualize_apic_accesses";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace enable_ept
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1ULL;
        constexpr const auto name = "enable_ept";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace descriptor_table_exiting
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "descriptor_table_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace enable_rdtscp
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "enable_rdtscp";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace virtualize_x2apic_mode
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4ULL;
        constexpr const auto name = "virtualize_x2apic_mode";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace enable_vpid
    {
        constexpr const auto mask = 0x0000000000000020ULL;
        constexpr const auto from = 5ULL;
        constexpr const auto name = "enable_vpid";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace wbinvd_exiting
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6ULL;
        constexpr const auto name = "wbinvd_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace unrestricted_guest
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7ULL;
        constexpr const auto name = "unrestricted_guest";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace apic_register_virtualization
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "apic_register_virtualization";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace virtual_interrupt_delivery
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9ULL;
        constexpr const auto name = "virtual_interrupt_delivery";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace pause_loop_exiting
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "pause_loop_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace rdrand_exiting
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "rdrand_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace enable_invpcid
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "enable_invpcid";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace enable_vm_functions
    {
        constexpr const auto mask = 0x0000000000002000ULL;
        constexpr const auto from = 13ULL;
        constexpr const auto name = "enable_vm_functions";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace vmcs_shadowing
    {
        constexpr const auto mask = 0x0000000000004000ULL;
        constexpr const auto from = 14ULL;
        constexpr const auto name = "vmcs_shadowing";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace enable_encls_exiting
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15ULL;
        constexpr const auto name = "enable_encls_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace rdseed_exiting
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "rdseed_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace enable_pml
    {
        constexpr const auto mask = 0x0000000000020000ULL;
        constexpr const auto from = 17ULL;
        constexpr const auto name = "enable_pml";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace ept_violation_ve
    {
        constexpr const auto mask = 0x0000000000040000ULL;
        constexpr const auto from = 18ULL;
        constexpr const auto name = "ept_violation_ve";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace pt_conceal_nonroot_operation
    {
        constexpr const auto mask = 0x0000000000080000ULL;
        constexpr const auto from = 19ULL;
        constexpr const auto name = "pt_conceal_nonroot_operation";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace enable_xsaves_xrstors
    {
        constexpr const auto mask = 0x0000000000100000ULL;
        constexpr const auto from = 20ULL;
        constexpr const auto name = "enable_xsaves_xrstors";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace ept_mode_based_control
    {
        constexpr const auto mask = 0x0000000000400000ULL;
        constexpr const auto from = 22ULL;
        constexpr const auto name = "ept_mode_based_control";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace use_tsc_scaling
    {
        constexpr const auto mask = 0x0000000002000000ULL;
        constexpr const auto from = 25ULL;
        constexpr const auto name = "use_tsc_scaling";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        virtualize_apic_accesses::dump(level, msg);
        enable_ept::dump(level, msg);
        descriptor_table_exiting::dump(level, msg);
        enable_rdtscp::dump(level, msg);
        virtualize_x2apic_mode::dump(level, msg);
        enable_vpid::dump(level, msg);
        wbinvd_exiting::dump(level, msg);
        unrestricted_guest::dump(level, msg);
        apic_register_virtualization::dump(level, msg);
        virtual_interrupt_delivery::dump(level, msg);
        pause_loop_exiting::dump(level, msg);
        rdrand_exiting::dump(level, msg);
        enable_invpcid::dump(level, msg);
        enable_vm_functions::dump(level, msg);
        vmcs_shadowing::dump(level, msg);
        enable_encls_exiting::dump(level, msg);
        rdseed_exiting::dump(level, msg);
        enable_pml::dump(level, msg);
        ept_violation_ve::dump(level, msg);
        pt_conceal_nonroot_operation::dump(level, msg);
        enable_xsaves_xrstors::dump(level, msg);
        ept_mode_based_control::dump(level, msg);
        use_tsc_scaling::dump(level, msg);
    }
}

namespace ia32_vmx_ept_vpid_cap
{
    constexpr const auto addr = 0x0000048CU;
    constexpr const auto name = "ia32_vmx_ept_vpid_cap";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace execute_only_translation
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "execute_only_translation";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace page_walk_length_of_4
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6ULL;
        constexpr const auto name = "page_walk_length_of_4";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace memory_type_uncacheable_supported
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "memory_type_uncacheable_supported";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace memory_type_write_back_supported
    {
        constexpr const auto mask = 0x0000000000004000ULL;
        constexpr const auto from = 14ULL;
        constexpr const auto name = "memory_type_write_back_supported";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pde_2mb_support
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "pde_2mb_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pdpte_1gb_support
    {
        constexpr const auto mask = 0x0000000000020000ULL;
        constexpr const auto from = 17ULL;
        constexpr const auto name = "pdpte_1gb_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace invept_support
    {
        constexpr const auto mask = 0x0000000000100000ULL;
        constexpr const auto from = 20ULL;
        constexpr const auto name = "invept_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace accessed_dirty_support
    {
        constexpr const auto mask = 0x0000000000200000ULL;
        constexpr const auto from = 21ULL;
        constexpr const auto name = "accessed_dirty_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace invept_single_context_support
    {
        constexpr const auto mask = 0x0000000002000000ULL;
        constexpr const auto from = 25ULL;
        constexpr const auto name = "invept_single_context_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace invept_all_context_support
    {
        constexpr const auto mask = 0x0000000004000000ULL;
        constexpr const auto from = 26ULL;
        constexpr const auto name = "invept_all_context_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace invvpid_support
    {
        constexpr const auto mask = 0x0000000100000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "invvpid_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace invvpid_individual_address_support
    {
        constexpr const auto mask = 0x0000010000000000ULL;
        constexpr const auto from = 40ULL;
        constexpr const auto name = "invvpid_individual_address_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace invvpid_single_context_support
    {
        constexpr const auto mask = 0x0000020000000000ULL;
        constexpr const auto from = 41ULL;
        constexpr const auto name = "invvpid_single_context_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace invvpid_all_context_support
    {
        constexpr const auto mask = 0x0000040000000000ULL;
        constexpr const auto from = 42ULL;
        constexpr const auto name = "invvpid_all_context_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace invvpid_single_context_retaining_globals_support
    {
        constexpr const auto mask = 0x0000080000000000ULL;
        constexpr const auto from = 43ULL;
        constexpr const auto name = "invvpid_single_context_retaining_globals_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        execute_only_translation::dump(level, msg);
        page_walk_length_of_4::dump(level, msg);
        memory_type_uncacheable_supported::dump(level, msg);
        memory_type_write_back_supported::dump(level, msg);
        pde_2mb_support::dump(level, msg);
        pdpte_1gb_support::dump(level, msg);
        invept_support::dump(level, msg);
        accessed_dirty_support::dump(level, msg);
        invept_single_context_support::dump(level, msg);
        invept_all_context_support::dump(level, msg);
        invvpid_support::dump(level, msg);
        invvpid_individual_address_support::dump(level, msg);
        invvpid_single_context_support::dump(level, msg);
        invvpid_all_context_support::dump(level, msg);
        invvpid_single_context_retaining_globals_support::dump(level, msg);
    }
}

namespace ia32_vmx_true_pinbased_ctls
{
    constexpr const auto addr = 0x0000048DU;
    constexpr const auto name = "ia32_vmx_true_pinbased_ctls";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto allowed0()
    { return (_read_msr(addr) & 0x00000000FFFFFFFFULL); }

    inline auto allowed1()
    { return ((_read_msr(addr) & 0xFFFFFFFF00000000ULL) >> 32); }

    namespace external_interrupt_exiting
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "external_interrupt_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace nmi_exiting
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "nmi_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace virtual_nmis
    {
        constexpr const auto mask = 0x0000000000000020ULL;
        constexpr const auto from = 5ULL;
        constexpr const auto name = "virtual_nmis";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace activate_vmx_preemption_timer
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6ULL;
        constexpr const auto name = "activate_vmx_preemption_timer";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace process_posted_interrupts
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7ULL;
        constexpr const auto name = "process_posted_interrupts";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        external_interrupt_exiting::dump(level, msg);
        nmi_exiting::dump(level, msg);
        virtual_nmis::dump(level, msg);
        activate_vmx_preemption_timer::dump(level, msg);
        process_posted_interrupts::dump(level, msg);
    }
}

namespace ia32_vmx_true_procbased_ctls
{
    constexpr const auto addr = 0x0000048EU;
    constexpr const auto name = "ia32_vmx_true_procbased_ctls";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto allowed0()
    { return (_read_msr(addr) & 0x00000000FFFFFFFFULL); }

    inline auto allowed1()
    { return ((_read_msr(addr) & 0xFFFFFFFF00000000ULL) >> 32); }

    namespace interrupt_window_exiting
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "interrupt_window_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace use_tsc_offsetting
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "use_tsc_offsetting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace hlt_exiting
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7ULL;
        constexpr const auto name = "hlt_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace invlpg_exiting
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9ULL;
        constexpr const auto name = "invlpg_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace mwait_exiting
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "mwait_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace rdpmc_exiting
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "rdpmc_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace rdtsc_exiting
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "rdtsc_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace cr3_load_exiting
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15ULL;
        constexpr const auto name = "cr3_load_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace cr3_store_exiting
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "cr3_store_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace cr8_load_exiting
    {
        constexpr const auto mask = 0x0000000000080000ULL;
        constexpr const auto from = 19ULL;
        constexpr const auto name = "cr8_load_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace cr8_store_exiting
    {
        constexpr const auto mask = 0x0000000000100000ULL;
        constexpr const auto from = 20ULL;
        constexpr const auto name = "cr8_store_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace use_tpr_shadow
    {
        constexpr const auto mask = 0x0000000000200000ULL;
        constexpr const auto from = 21ULL;
        constexpr const auto name = "use_tpr_shadow";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace nmi_window_exiting
    {
        constexpr const auto mask = 0x0000000000400000ULL;
        constexpr const auto from = 22ULL;
        constexpr const auto name = "nmi_window_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace mov_dr_exiting
    {
        constexpr const auto mask = 0x0000000000800000ULL;
        constexpr const auto from = 23ULL;
        constexpr const auto name = "mov_dr_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace unconditional_io_exiting
    {
        constexpr const auto mask = 0x0000000001000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "unconditional_io_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace use_io_bitmaps
    {
        constexpr const auto mask = 0x0000000002000000ULL;
        constexpr const auto from = 25ULL;
        constexpr const auto name = "use_io_bitmaps";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace monitor_trap_flag
    {
        constexpr const auto mask = 0x0000000008000000ULL;
        constexpr const auto from = 27ULL;
        constexpr const auto name = "monitor_trap_flag";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace use_msr_bitmap
    {
        constexpr const auto mask = 0x0000000010000000ULL;
        constexpr const auto from = 28ULL;
        constexpr const auto name = "use_msr_bitmap";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace monitor_exiting
    {
        constexpr const auto mask = 0x0000000020000000ULL;
        constexpr const auto from = 29ULL;
        constexpr const auto name = "monitor_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace pause_exiting
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "pause_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace activate_secondary_controls
    {
        constexpr const auto mask = 0x0000000080000000ULL;
        constexpr const auto from = 31ULL;
        constexpr const auto name = "activate_secondary_controls";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        interrupt_window_exiting::dump(level, msg);
        use_tsc_offsetting::dump(level, msg);
        hlt_exiting::dump(level, msg);
        invlpg_exiting::dump(level, msg);
        mwait_exiting::dump(level, msg);
        rdpmc_exiting::dump(level, msg);
        rdtsc_exiting::dump(level, msg);
        cr3_load_exiting::dump(level, msg);
        cr3_store_exiting::dump(level, msg);
        cr8_load_exiting::dump(level, msg);
        cr8_store_exiting::dump(level, msg);
        use_tpr_shadow::dump(level, msg);
        nmi_window_exiting::dump(level, msg);
        mov_dr_exiting::dump(level, msg);
        unconditional_io_exiting::dump(level, msg);
        use_io_bitmaps::dump(level, msg);
        monitor_trap_flag::dump(level, msg);
        use_msr_bitmap::dump(level, msg);
        monitor_exiting::dump(level, msg);
        pause_exiting::dump(level, msg);
        activate_secondary_controls::dump(level, msg);
    }
}

namespace ia32_vmx_true_exit_ctls
{
    constexpr const auto addr = 0x0000048FU;
    constexpr const auto name = "ia32_vmx_true_exit_ctls";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto allowed0()
    { return (_read_msr(addr) & 0x00000000FFFFFFFFULL); }

    inline auto allowed1()
    { return ((_read_msr(addr) & 0xFFFFFFFF00000000ULL) >> 32); }

    namespace save_debug_controls
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "save_debug_controls";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace host_address_space_size
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9ULL;
        constexpr const auto name = "host_address_space_size";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace load_ia32_perf_global_ctrl
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "load_ia32_perf_global_ctrl";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace acknowledge_interrupt_on_exit
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15ULL;
        constexpr const auto name = "acknowledge_interrupt_on_exit";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace save_ia32_pat
    {
        constexpr const auto mask = 0x0000000000040000ULL;
        constexpr const auto from = 18ULL;
        constexpr const auto name = "save_ia32_pat";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace load_ia32_pat
    {
        constexpr const auto mask = 0x0000000000080000ULL;
        constexpr const auto from = 19ULL;
        constexpr const auto name = "load_ia32_pat";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace save_ia32_efer
    {
        constexpr const auto mask = 0x0000000000100000ULL;
        constexpr const auto from = 20ULL;
        constexpr const auto name = "save_ia32_efer";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace load_ia32_efer
    {
        constexpr const auto mask = 0x0000000000200000ULL;
        constexpr const auto from = 21ULL;
        constexpr const auto name = "load_ia32_efer";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace save_vmx_preemption_timer_value
    {
        constexpr const auto mask = 0x0000000000400000ULL;
        constexpr const auto from = 22ULL;
        constexpr const auto name = "save_vmx_preemption_timer_value";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace clear_ia32_bndcfgs
    {
        constexpr const auto mask = 0x0000000000800000ULL;
        constexpr const auto from = 23ULL;
        constexpr const auto name = "clear_ia32_bndcfgs";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        save_debug_controls::dump(level, msg);
        host_address_space_size::dump(level, msg);
        load_ia32_perf_global_ctrl::dump(level, msg);
        acknowledge_interrupt_on_exit::dump(level, msg);
        save_ia32_pat::dump(level, msg);
        load_ia32_pat::dump(level, msg);
        save_ia32_efer::dump(level, msg);
        load_ia32_efer::dump(level, msg);
        save_vmx_preemption_timer_value::dump(level, msg);
        clear_ia32_bndcfgs::dump(level, msg);
    }
}

namespace ia32_vmx_true_entry_ctls
{
    constexpr const auto addr = 0x00000490U;
    constexpr const auto name = "ia32_vmx_true_entry_ctls";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto allowed0()
    { return (_read_msr(addr) & 0x00000000FFFFFFFFULL); }

    inline auto allowed1()
    { return ((_read_msr(addr) & 0xFFFFFFFF00000000ULL) >> 32); }

    namespace load_debug_controls
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "load_debug_controls";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace ia_32e_mode_guest
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9ULL;
        constexpr const auto name = "ia_32e_mode_guest";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace entry_to_smm
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "entry_to_smm";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace deactivate_dual_monitor_treatment
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "deactivate_dual_monitor_treatment";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace load_ia32_perf_global_ctrl
    {
        constexpr const auto mask = 0x0000000000002000ULL;
        constexpr const auto from = 13ULL;
        constexpr const auto name = "load_ia32_perf_global_ctrl";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace load_ia32_pat
    {
        constexpr const auto mask = 0x0000000000004000ULL;
        constexpr const auto from = 14ULL;
        constexpr const auto name = "load_ia32_pat";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace load_ia32_efer
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15ULL;
        constexpr const auto name = "load_ia32_efer";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    namespace load_ia32_bndcfgs
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "load_ia32_bndcfgs";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_allowed1(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        load_debug_controls::dump(level, msg);
        ia_32e_mode_guest::dump(level, msg);
        entry_to_smm::dump(level, msg);
        deactivate_dual_monitor_treatment::dump(level, msg);
        load_ia32_perf_global_ctrl::dump(level, msg);
        load_ia32_pat::dump(level, msg);
        load_ia32_efer::dump(level, msg);
        load_ia32_bndcfgs::dump(level, msg);
    }
}

namespace ia32_vmx_vmfunc
{
    constexpr const auto addr = 0x00000491U;
    constexpr const auto name = "ia32_vmx_vmfunc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace eptp_switching
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "eptp_switching";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        eptp_switching::dump(level, msg);
    }
}

namespace ia32_a_pmc0
{
    constexpr const auto addr = 0x000004C1U;
    constexpr const auto name = "ia32_a_pmc0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_a_pmc1
{
    constexpr const auto addr = 0x000004C2U;
    constexpr const auto name = "ia32_a_pmc1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_a_pmc2
{
    constexpr const auto addr = 0x000004C3U;
    constexpr const auto name = "ia32_a_pmc2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_a_pmc3
{
    constexpr const auto addr = 0x000004C4U;
    constexpr const auto name = "ia32_a_pmc3";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_a_pmc4
{
    constexpr const auto addr = 0x000004C5U;
    constexpr const auto name = "ia32_a_pmc4";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_a_pmc5
{
    constexpr const auto addr = 0x000004C6U;
    constexpr const auto name = "ia32_a_pmc5";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_a_pmc6
{
    constexpr const auto addr = 0x000004C7U;
    constexpr const auto name = "ia32_a_pmc6";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_a_pmc7
{
    constexpr const auto addr = 0x000004C8U;
    constexpr const auto name = "ia32_a_pmc7";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mcg_ext_ctl
{
    constexpr const auto addr = 0x000004D0U;
    constexpr const auto name = "ia32_mcg_ext_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace lmce_en
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "lmce_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        lmce_en::dump(level, msg);
    }
}

namespace ia32_sgx_svn_sinit
{
    constexpr const auto addr = 0x00000500U;
    constexpr const auto name = "ia32_sgx_svn_sinit";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace lock
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "lock";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace sgx_svn_sinit
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "sgx_svn_sinit";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        lock::dump(level, msg);
        sgx_svn_sinit::dump(level, msg);
    }
}

namespace ia32_rtit_output_base
{
    constexpr const auto addr = 0x00000560U;
    constexpr const auto name = "ia32_rtit_output_base";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace base_phys_address
    {
        constexpr const auto mask = 0x7FFFFFFFFFFFFF80ULL;
        constexpr const auto from = 7ULL;
        constexpr const auto name = "base_phys_address";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        base_phys_address::dump(level, msg);
    }
}

namespace ia32_rtit_output_mask_ptrs
{
    constexpr const auto addr = 0x00000561U;
    constexpr const auto name = "ia32_rtit_output_mask_ptrs";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace mask_table_offset
    {
        constexpr const auto mask = 0x00000000FFFFFF80ULL;
        constexpr const auto from = 7ULL;
        constexpr const auto name = "mask_table_offset";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace output_offset
    {
        constexpr const auto mask = 0xFFFFFFFF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "output_offset";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        mask_table_offset::dump(level, msg);
        output_offset::dump(level, msg);
    }
}

namespace ia32_rtit_ctl
{
    constexpr const auto addr = 0x00000570U;
    constexpr const auto name = "ia32_rtit_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace traceen
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "traceen";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace cycen
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1ULL;
        constexpr const auto name = "cycen";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace os
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "os";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace user
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "user";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace fabricen
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6ULL;
        constexpr const auto name = "fabricen";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace cr3_filter
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7ULL;
        constexpr const auto name = "cr3_filter";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace topa
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "topa";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace mtcen
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9ULL;
        constexpr const auto name = "mtcen";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace tscen
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "tscen";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace disretc
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "disretc";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace branchen
    {
        constexpr const auto mask = 0x0000000000002000ULL;
        constexpr const auto from = 13ULL;
        constexpr const auto name = "branchen";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace mtcfreq
    {
        constexpr const auto mask = 0x000000000003C000ULL;
        constexpr const auto from = 14ULL;
        constexpr const auto name = "mtcfreq";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cycthresh
    {
        constexpr const auto mask = 0x0000000000780000ULL;
        constexpr const auto from = 19ULL;
        constexpr const auto name = "cycthresh";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace psbfreq
    {
        constexpr const auto mask = 0x000000000F000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "psbfreq";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace addr0_cfg
    {
        constexpr const auto mask = 0x0000000F00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "addr0_cfg";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace addr1_cfg
    {
        constexpr const auto mask = 0x000000F000000000ULL;
        constexpr const auto from = 36ULL;
        constexpr const auto name = "addr1_cfg";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace addr2_cfg
    {
        constexpr const auto mask = 0x00000F0000000000ULL;
        constexpr const auto from = 40ULL;
        constexpr const auto name = "addr2_cfg";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace addr3_cfg
    {
        constexpr const auto mask = 0x0000F00000000000ULL;
        constexpr const auto from = 44ULL;
        constexpr const auto name = "addr3_cfg";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        traceen::dump(level, msg);
        cycen::dump(level, msg);
        os::dump(level, msg);
        user::dump(level, msg);
        fabricen::dump(level, msg);
        cr3_filter::dump(level, msg);
        topa::dump(level, msg);
        mtcen::dump(level, msg);
        tscen::dump(level, msg);
        disretc::dump(level, msg);
        branchen::dump(level, msg);
        mtcfreq::dump(level, msg);
        cycthresh::dump(level, msg);
        psbfreq::dump(level, msg);
        addr0_cfg::dump(level, msg);
        addr1_cfg::dump(level, msg);
        addr2_cfg::dump(level, msg);
        addr3_cfg::dump(level, msg);
    }
}

namespace ia32_rtit_status
{
    constexpr const auto addr = 0x00000571U;
    constexpr const auto name = "ia32_rtit_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace filteren
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "filteren";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace contexen
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1ULL;
        constexpr const auto name = "contexen";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace triggeren
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "triggeren";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace error
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4ULL;
        constexpr const auto name = "error";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace stopped
    {
        constexpr const auto mask = 0x0000000000000020ULL;
        constexpr const auto from = 5ULL;
        constexpr const auto name = "stopped";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace packetbytecnt
    {
        constexpr const auto mask = 0x0001FFFF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "packetbytecnt";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        filteren::dump(level, msg);
        contexen::dump(level, msg);
        triggeren::dump(level, msg);
        error::dump(level, msg);
        stopped::dump(level, msg);
        packetbytecnt::dump(level, msg);
    }
}

namespace ia32_rtit_cr3_match
{
    constexpr const auto addr = 0x00000572U;
    constexpr const auto name = "ia32_rtit_cr3_match";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace cr3
    {
        constexpr const auto mask = 0xFFFFFFFFFFFFFFE0ULL;
        constexpr const auto from = 5ULL;
        constexpr const auto name = "cr3";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        cr3::dump(level, msg);
    }
}

namespace ia32_rtit_addr0_a
{
    constexpr const auto addr = 0x00000580U;
    constexpr const auto name = "ia32_rtit_addr0_a";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace virtual_address
    {
        constexpr const auto mask = 0x0000FFFFFFFFFFFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "virtual_address";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace signext_va
    {
        constexpr const auto mask = 0xFFFF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "signext_va";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        virtual_address::dump(level, msg);
        signext_va::dump(level, msg);
    }
}

namespace ia32_rtit_addr0_b
{
    constexpr const auto addr = 0x00000581U;
    constexpr const auto name = "ia32_rtit_addr0_b";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace virtual_address
    {
        constexpr const auto mask = 0x0000FFFFFFFFFFFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "virtual_address";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace signext_va
    {
        constexpr const auto mask = 0xFFFF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "signext_va";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        virtual_address::dump(level, msg);
        signext_va::dump(level, msg);
    }
}

namespace ia32_rtit_addr1_a
{
    constexpr const auto addr = 0x00000582U;
    constexpr const auto name = "ia32_rtit_addr1_a";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace virtual_address
    {
        constexpr const auto mask = 0x0000FFFFFFFFFFFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "virtual_address";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace signext_va
    {
        constexpr const auto mask = 0xFFFF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "signext_va";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        virtual_address::dump(level, msg);
        signext_va::dump(level, msg);
    }
}

namespace ia32_rtit_addr1_b
{
    constexpr const auto addr = 0x00000583U;
    constexpr const auto name = "ia32_rtit_addr1_b";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace virtual_address
    {
        constexpr const auto mask = 0x0000FFFFFFFFFFFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "virtual_address";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace signext_va
    {
        constexpr const auto mask = 0xFFFF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "signext_va";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        virtual_address::dump(level, msg);
        signext_va::dump(level, msg);
    }
}

namespace ia32_rtit_addr2_a
{
    constexpr const auto addr = 0x00000584U;
    constexpr const auto name = "ia32_rtit_addr2_a";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace virtual_address
    {
        constexpr const auto mask = 0x0000FFFFFFFFFFFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "virtual_address";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace signext_va
    {
        constexpr const auto mask = 0xFFFF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "signext_va";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        virtual_address::dump(level, msg);
        signext_va::dump(level, msg);
    }
}

namespace ia32_rtit_addr2_b
{
    constexpr const auto addr = 0x00000585U;
    constexpr const auto name = "ia32_rtit_addr2_b";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace virtual_address
    {
        constexpr const auto mask = 0x0000FFFFFFFFFFFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "virtual_address";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace signext_va
    {
        constexpr const auto mask = 0xFFFF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "signext_va";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        virtual_address::dump(level, msg);
        signext_va::dump(level, msg);
    }
}

namespace ia32_rtit_addr3_a
{
    constexpr const auto addr = 0x00000586U;
    constexpr const auto name = "ia32_rtit_addr3_a";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace virtual_address
    {
        constexpr const auto mask = 0x0000FFFFFFFFFFFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "virtual_address";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace signext_va
    {
        constexpr const auto mask = 0xFFFF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "signext_va";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        virtual_address::dump(level, msg);
        signext_va::dump(level, msg);
    }
}

namespace ia32_rtit_addr3_b
{
    constexpr const auto addr = 0x00000587U;
    constexpr const auto name = "ia32_rtit_addr3_b";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace virtual_address
    {
        constexpr const auto mask = 0x0000FFFFFFFFFFFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "virtual_address";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace signext_va
    {
        constexpr const auto mask = 0xFFFF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "signext_va";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        virtual_address::dump(level, msg);
        signext_va::dump(level, msg);
    }
}

namespace ia32_ds_area
{
    constexpr const auto addr = 0x00000600U;
    constexpr const auto name = "ia32_ds_area";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_tsc_deadline
{
    constexpr const auto addr = 0x000006E0U;
    constexpr const auto name = "ia32_tsc_deadline";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_pm_enable
{
    constexpr const auto addr = 0x00000770U;
    constexpr const auto name = "ia32_pm_enable";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace hwp
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "sce";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        hwp::dump(level, msg);
    }
}

namespace ia32_hwp_capabilities
{
    constexpr const auto addr = 0x00000771U;
    constexpr const auto name = "ia32_hwp_capabilities";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace highest_perf
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "highest_perf";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace guaranteed_perf
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "guaranteed_perf";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace most_efficient_perf
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "most_efficient_perf";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace lowest_perf
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "lowest_perf";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        highest_perf::dump(level, msg);
        guaranteed_perf::dump(level, msg);
        most_efficient_perf::dump(level, msg);
        lowest_perf::dump(level, msg);
    }
}

namespace ia32_hwp_request_pkg
{
    constexpr const auto addr = 0x00000772U;
    constexpr const auto name = "ia32_hwp_request_pkg";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace min_perf
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "min_perf";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace max_perf
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "max_perf";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace desired_perf
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "desired_perf";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace energy_perf_pref
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "energy_perf_pref";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace activity_window
    {
        constexpr const auto mask = 0x000003FF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "activity_window";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        min_perf::dump(level, msg);
        max_perf::dump(level, msg);
        desired_perf::dump(level, msg);
        energy_perf_pref::dump(level, msg);
        activity_window::dump(level, msg);
    }
}

namespace ia32_hwp_interrupt
{
    constexpr const auto addr = 0x00000773U;
    constexpr const auto name = "ia32_hwp_interrupt";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace perf_change
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "perf_change";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace excursion_min
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1ULL;
        constexpr const auto name = "excursion_min";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        perf_change::dump(level, msg);
        excursion_min::dump(level, msg);
    }
}

namespace ia32_hwp_request
{
    constexpr const auto addr = 0x00000774U;
    constexpr const auto name = "ia32_hwp_request";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace min_perf
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "min_perf";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace max_perf
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "max_perf";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace desired_perf
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "desired_perf";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace energy_perf_pref
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "energy_perf_pref";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace activity_window
    {
        constexpr const auto mask = 0x000003FF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "energy_perf_pref";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace package_control
    {
        constexpr const auto mask = 0x0000040000000000ULL;
        constexpr const auto from = 42ULL;
        constexpr const auto name = "package_control";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        min_perf::dump(level, msg);
        max_perf::dump(level, msg);
        desired_perf::dump(level, msg);
        energy_perf_pref::dump(level, msg);
        activity_window::dump(level, msg);
        package_control::dump(level, msg);
    }
}

namespace ia32_hwp_status
{
    constexpr const auto addr = 0x00000777U;
    constexpr const auto name = "ia32_hwp_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace perf_change
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "perf_change";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace excursion_to_min
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "excursion_to_min";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        perf_change::dump(level, msg);
        excursion_to_min::dump(level, msg);
    }
}

namespace ia32_debug_interface
{
    constexpr const auto addr = 0x00000C80U;
    constexpr const auto name = "ia32_debug_interface";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace enable
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "enable";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace lock
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "lock";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace debug_occurred
    {
        constexpr const auto mask = 0x0000000080000000ULL;
        constexpr const auto from = 31ULL;
        constexpr const auto name = "debug_occurred";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        enable::dump(level, msg);
        lock::dump(level, msg);
        debug_occurred::dump(level, msg);
    }
}

namespace ia32_l3_qos_cfg
{
    constexpr const auto addr = 0x00000C81U;
    constexpr const auto name = "ia32_l3_qos_cfg";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace enable
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "enable";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        enable::dump(level, msg);
    }
}

namespace ia32_qm_evtsel
{
    constexpr const auto addr = 0x00000C8DU;
    constexpr const auto name = "ia32_qm_evtsel";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace event_id
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "event_id";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace resource_monitoring_id
    {
        constexpr const auto mask = 0xFFFFFFFF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "resource_monitoring_id";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        event_id::dump(level, msg);
        resource_monitoring_id::dump(level, msg);
    }
}

namespace ia32_qm_ctr
{
    constexpr const auto addr = 0x00000C8EU;
    constexpr const auto name = "ia32_qm_ctr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace resource_monitored_data
    {
        constexpr const auto mask = 0x3FFFFFFFFFFFFFFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "resource_monitored_data";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace unavailable
    {
        constexpr const auto mask = 0x4000000000000000ULL;
        constexpr const auto from = 62ULL;
        constexpr const auto name = "unavailable";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace error
    {
        constexpr const auto mask = 0x8000000000000000ULL;
        constexpr const auto from = 63ULL;
        constexpr const auto name = "error";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        resource_monitored_data::dump(level, msg);
        unavailable::dump(level, msg);
        error::dump(level, msg);
    }
}

namespace ia32_pqr_assoc
{
    constexpr const auto addr = 0x00000C8FU;
    constexpr const auto name = "ia32_pqr_assoc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace resource_monitoring_id
    {
        constexpr const auto mask = 0x00000000FFFFFFFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "resource_monitoring_id";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cos
    {
        constexpr const auto mask = 0xFFFFFFFF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "cos";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        resource_monitoring_id::dump(level, msg);
        cos::dump(level, msg);
    }
}

namespace ia32_bndcfgs
{
    constexpr const auto addr = 0x00000D90U;
    constexpr const auto name = "ia32_bndcfgs";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace en
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace bndpreserve
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1ULL;
        constexpr const auto name = "bndpreserve";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace base_address
    {
        constexpr const auto mask = 0xFFFFFFFFFFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "base_address";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        en::dump(level, msg);
        bndpreserve::dump(level, msg);
        base_address::dump(level, msg);
    }
}

namespace ia32_xss
{
    constexpr const auto addr = 0x00000DA0U;
    constexpr const auto name = "ia32_xss";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace trace_packet
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "trace_packet";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        trace_packet::dump(level, msg);
    }
}

namespace ia32_pkg_hdc_ctl
{
    constexpr const auto addr = 0x00000DB0U;
    constexpr const auto name = "ia32_pkg_hdc_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace hdc_pkg_enable
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "hdc_pkg_enable";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        hdc_pkg_enable::dump(level, msg);
    }
}

namespace ia32_pm_ctl1
{
    constexpr const auto addr = 0x00000DB1U;
    constexpr const auto name = "ia32_pm_ctl1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace hdc_allow_block
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "hdc_allow_block";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        hdc_allow_block::dump(level, msg);
    }
}

namespace ia32_thread_stall
{
    constexpr const auto addr = 0x00000DB2U;
    constexpr const auto name = "ia32_thread_stall";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace stall_cycle_cnt
    {
        constexpr const auto mask = 0xFFFFFFFFFFFFFFFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "stall_cycle_cnt";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        stall_cycle_cnt::dump(level, msg);
    }
}

namespace ia32_efer
{
    constexpr const auto addr = 0xC0000080U;
    constexpr const auto name = "ia32_efer";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace sce
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "sce";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace lme
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "lme";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace lma
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "lma";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace nxe
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "lma";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        sce::dump(level, msg);
        lme::dump(level, msg);
        lma::dump(level, msg);
        nxe::dump(level, msg);
    }
}

namespace ia32_fs_base
{
    constexpr const auto addr = 0xC0000100U;
    constexpr const auto name = "ia32_fs_base";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_gs_base
{
    constexpr const auto addr = 0xC0000101U;
    constexpr const auto name = "ia32_gs_base";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

}
}

// *INDENT-ON*

#endif
