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

#ifndef MSRS_INTEL_X64_H
#define MSRS_INTEL_X64_H

#include <gsl/gsl>

#include <debug.h>
#include <bitmanip.h>

extern "C" uint64_t __read_msr(uint32_t addr) noexcept;
extern "C" void __write_msr(uint32_t addr, uint64_t val) noexcept;

// *INDENT-OFF*

namespace intel_x64
{
namespace msrs
{
    using field_type = uint32_t;
    using value_type = uint64_t;

    template<class A> inline auto get(A addr) noexcept
    { return __read_msr(gsl::narrow_cast<field_type>(addr)); }

    template<class A, class T> void set(A addr, T val) noexcept
    { __write_msr(gsl::narrow_cast<field_type>(addr), val); }

    namespace ia32_feature_control
    {
        constexpr const auto addr = 0x0000003AU;
        constexpr const auto name = "ia32_feature_control";

        inline auto get() noexcept
        { return __read_msr(addr); }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val) noexcept { __write_msr(addr, val); }

        namespace lock_bit
        {
            constexpr const auto mask = 0x0000000000000001UL;
            constexpr const auto from = 0;
            constexpr const auto name = "lock_bit";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace enable_vmx_inside_smx
        {
            constexpr const auto mask = 0x0000000000000002UL;
            constexpr const auto from = 1;
            constexpr const auto name = "enable_vmx_inside_smx";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace enable_vmx_outside_smx
        {
            constexpr const auto mask = 0x0000000000000004UL;
            constexpr const auto from = 2;
            constexpr const auto name = "enable_vmx_outside_smx";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace senter_local_function_enables
        {
            constexpr const auto mask = 0x0000000000007F00UL;
            constexpr const auto from = 8;
            constexpr const auto name = "senter_local_function_enables";

            inline auto get() noexcept
            { return get_bits(__read_msr(addr), mask) >> from; }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set(T val) noexcept { __write_msr(addr, set_bits(__read_msr(addr), mask, val << from)); }
        }

        namespace senter_gloabl_function_enable
        {
            constexpr const auto mask = 0x0000000000008000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "senter_gloabl_function_enables";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace sgx_launch_control_enable
        {
            constexpr const auto mask = 0x0000000000020000UL;
            constexpr const auto from = 17;
            constexpr const auto name = "sgx_launch_control_enable";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace sgx_global_enable
        {
            constexpr const auto mask = 0x0000000000040000UL;
            constexpr const auto from = 18;
            constexpr const auto name = "sgx_global_enable";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace lmce
        {
            constexpr const auto mask = 0x0000000000100000UL;
            constexpr const auto from = 20;
            constexpr const auto name = "lmce";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        inline void dump() noexcept
        {
            bfdebug << "msrs::ia32_feature_control enabled flags:" << bfendl;

            if (lock_bit::get())
                bfdebug << "    - " << lock_bit::name << bfendl;
            if (enable_vmx_inside_smx::get())
                bfdebug << "    - " << enable_vmx_inside_smx::name << bfendl;
            if (enable_vmx_outside_smx::get())
                bfdebug << "    - " << enable_vmx_outside_smx::name << bfendl;
            if (senter_gloabl_function_enable::get())
                bfdebug << "    - " << senter_gloabl_function_enable::name << bfendl;
            if (sgx_launch_control_enable::get())
                bfdebug << "    - " << sgx_launch_control_enable::name << bfendl;
            if (sgx_global_enable::get())
                bfdebug << "    - " << sgx_global_enable::name << bfendl;
            if (lmce::get())
                bfdebug << "    - " << lmce::name << bfendl;

            bfdebug << bfendl;
            bfdebug << "msrs::ia32_feature_control fields:" << bfendl;

            bfdebug << "    - " << senter_local_function_enables::name << " = "
                    << view_as_pointer(senter_local_function_enables::get()) << bfendl;
        }
    }

    namespace ia32_sysenter_cs
    {
        constexpr const auto addr = 0x00000174U;
        constexpr const auto name = "ia32_sysenter_cs";

        inline auto get() noexcept
        { return __read_msr(addr); }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val) noexcept { __write_msr(addr, val); }
    }

    namespace ia32_sysenter_esp
    {
        constexpr const auto addr = 0x00000175U;
        constexpr const auto name = "ia32_sysenter_esp";

        inline auto get() noexcept
        { return __read_msr(addr); }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val) noexcept { __write_msr(addr, val); }
    }

    namespace ia32_sysenter_eip
    {
        constexpr const auto addr = 0x00000176;
        constexpr const auto name = "ia32_sysenter_eip";

        inline auto get() noexcept
        { return __read_msr(addr); }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val) noexcept { __write_msr(addr, val); }
    }

    namespace ia32_debugctl
    {
        constexpr const auto addr = 0x000001D9U;
        constexpr const auto name = "ia32_debugctl";

        inline auto get() noexcept
        { return __read_msr(addr); }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val) noexcept { __write_msr(addr, val); }

        namespace lbr
        {
            constexpr const auto mask = 0x0000000000000001UL;
            constexpr const auto from = 0;
            constexpr const auto name = "lbr";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace btf
        {
            constexpr const auto mask = 0x0000000000000002UL;
            constexpr const auto from = 1;
            constexpr const auto name = "btf";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace tr
        {
            constexpr const auto mask = 0x0000000000000040UL;
            constexpr const auto from = 6;
            constexpr const auto name = "tr";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace bts
        {
            constexpr const auto mask = 0x0000000000000080UL;
            constexpr const auto from = 7;
            constexpr const auto name = "bts";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace btint
        {
            constexpr const auto mask = 0x0000000000000100UL;
            constexpr const auto from = 8;
            constexpr const auto name = "btint";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace bt_off_os
        {
            constexpr const auto mask = 0x0000000000000200UL;
            constexpr const auto from = 9;
            constexpr const auto name = "bt_off_os";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace bt_off_user
        {
            constexpr const auto mask = 0x0000000000000400UL;
            constexpr const auto from = 10;
            constexpr const auto name = "bt_off_user";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace freeze_lbrs_on_pmi
        {
            constexpr const auto mask = 0x0000000000000800UL;
            constexpr const auto from = 11;
            constexpr const auto name = "freeze_lbrs_on_pmi";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace freeze_perfmon_on_pmi
        {
            constexpr const auto mask = 0x0000000000001000UL;
            constexpr const auto from = 12;
            constexpr const auto name = "freeze_perfmon_on_pmi";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace enable_uncore_pmi
        {
            constexpr const auto mask = 0x0000000000002000UL;
            constexpr const auto from = 13;
            constexpr const auto name = "enable_uncore_pmi";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace freeze_while_smm
        {
            constexpr const auto mask = 0x0000000000004000UL;
            constexpr const auto from = 14;
            constexpr const auto name = "freeze_while_smm";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace rtm_debug
        {
            constexpr const auto mask = 0x0000000000008000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "rtm_debug";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace reserved
        {
            constexpr const auto mask = 0xFFFFFFFFFFFF003CUL;
            constexpr const auto from = 0;
            constexpr const auto name = "reserved";

            inline auto get() noexcept
            { return get_bits(__read_msr(addr), mask) >> from; }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set(T val) noexcept { __write_msr(addr, set_bits(__read_msr(addr), mask, val << from)); }
        }

        inline void dump() noexcept
        {
            bfdebug << "msrs::ia32_debugctl enabled flags:" << bfendl;

            if (lbr::get())
                bfdebug << "    - " << lbr::name << bfendl;
            if (btf::get())
                bfdebug << "    - " << btf::name << bfendl;
            if (tr::get())
                bfdebug << "    - " << tr::name << bfendl;
            if (bts::get())
                bfdebug << "    - " << bts::name << bfendl;
            if (btint::get())
                bfdebug << "    - " << btint::name << bfendl;
            if (bt_off_os::get())
                bfdebug << "    - " << bt_off_os::name << bfendl;
            if (bt_off_user::get())
                bfdebug << "    - " << bt_off_user::name << bfendl;
            if (freeze_lbrs_on_pmi::get())
                bfdebug << "    - " << freeze_lbrs_on_pmi::name << bfendl;
            if (freeze_perfmon_on_pmi::get())
                bfdebug << "    - " << freeze_perfmon_on_pmi::name << bfendl;
            if (enable_uncore_pmi::get())
                bfdebug << "    - " << enable_uncore_pmi::name << bfendl;
            if (freeze_while_smm::get())
                bfdebug << "    - " << freeze_while_smm::name << bfendl;
            if (rtm_debug::get())
                bfdebug << "    - " << rtm_debug::name << bfendl;
        }
    }

    namespace ia32_pat
    {
        constexpr const auto addr = 0x00000277U;
        constexpr const auto name = "ia32_pat";

        inline auto get() noexcept
        { return __read_msr(addr); }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val) noexcept { __write_msr(addr, val); }

        namespace pa0
        {
            constexpr const auto mask = 0x0000000000000007UL;
            constexpr const auto from = 0;
            constexpr const auto name = "pa0";

            inline auto get() noexcept
            { return get_bits(__read_msr(addr), mask) >> from; }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set(T val) noexcept { __write_msr(addr, set_bits(__read_msr(addr), mask, val << from)); }
        }

        namespace pa1
        {
            constexpr const auto mask = 0x0000000000000700UL;
            constexpr const auto from = 8;
            constexpr const auto name = "pa1";

            inline auto get() noexcept
            { return get_bits(__read_msr(addr), mask) >> from; }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set(T val) noexcept { __write_msr(addr, set_bits(__read_msr(addr), mask, val << from)); }
        }

        namespace pa2
        {
            constexpr const auto mask = 0x0000000000070000UL;
            constexpr const auto from = 16;
            constexpr const auto name = "pa2";

            inline auto get() noexcept
            { return get_bits(__read_msr(addr), mask) >> from; }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set(T val) noexcept { __write_msr(addr, set_bits(__read_msr(addr), mask, val << from)); }
        }

        namespace pa3
        {
            constexpr const auto mask = 0x0000000007000000UL;
            constexpr const auto from = 24;
            constexpr const auto name = "pa3";

            inline auto get() noexcept
            { return get_bits(__read_msr(addr), mask) >> from; }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set(T val) noexcept { __write_msr(addr, set_bits(__read_msr(addr), mask, val << from)); }
        }

        namespace pa4
        {
            constexpr const auto mask = 0x0000000700000000UL;
            constexpr const auto from = 32;
            constexpr const auto name = "pa4";

            inline auto get() noexcept
            { return get_bits(__read_msr(addr), mask) >> from; }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set(T val) noexcept { __write_msr(addr, set_bits(__read_msr(addr), mask, val << from)); }
        }

        namespace pa5
        {
            constexpr const auto mask = 0x0000070000000000UL;
            constexpr const auto from = 40;
            constexpr const auto name = "pa5";

            inline auto get() noexcept
            { return get_bits(__read_msr(addr), mask) >> from; }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set(T val) noexcept { __write_msr(addr, set_bits(__read_msr(addr), mask, val << from)); }
        }

        namespace pa6
        {
            constexpr const auto mask = 0x0007000000000000UL;
            constexpr const auto from = 48;
            constexpr const auto name = "pa6";

            inline auto get() noexcept
            { return get_bits(__read_msr(addr), mask) >> from; }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set(T val) noexcept { __write_msr(addr, set_bits(__read_msr(addr), mask, val << from)); }
        }

        namespace pa7
        {
            constexpr const auto mask = 0x0700000000000000UL;
            constexpr const auto from = 56;
            constexpr const auto name = "pa7";

            inline auto get() noexcept
            { return get_bits(__read_msr(addr), mask) >> from; }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set(T val) noexcept { __write_msr(addr, set_bits(__read_msr(addr), mask, val << from)); }
        }

        inline void dump() noexcept
        {
            bfdebug << "msrs::ia32_pat fields:" << bfendl;

            bfdebug << "    - " << pa0::name << " = "
                    << view_as_pointer(pa0::get()) << bfendl;
            bfdebug << "    - " << pa1::name << " = "
                    << view_as_pointer(pa1::get()) << bfendl;
            bfdebug << "    - " << pa2::name << " = "
                    << view_as_pointer(pa2::get()) << bfendl;
            bfdebug << "    - " << pa3::name << " = "
                    << view_as_pointer(pa3::get()) << bfendl;
            bfdebug << "    - " << pa4::name << " = "
                    << view_as_pointer(pa4::get()) << bfendl;
            bfdebug << "    - " << pa5::name << " = "
                    << view_as_pointer(pa5::get()) << bfendl;
            bfdebug << "    - " << pa6::name << " = "
                    << view_as_pointer(pa6::get()) << bfendl;
            bfdebug << "    - " << pa7::name << " = "
                    << view_as_pointer(pa7::get()) << bfendl;
        }
    }

    namespace ia32_perf_global_ctrl
    {
        constexpr const auto addr = 0x0000038FU;
        constexpr const auto name = "ia32_perf_global_ctrl";

        inline auto get() noexcept
        { return __read_msr(addr); }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val) noexcept { __write_msr(addr, val); }

        namespace pmc0
        {
            constexpr const auto mask = 0x0000000000000001UL;
            constexpr const auto from = 0;
            constexpr const auto name = "pmc0";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace pmc1
        {
            constexpr const auto mask = 0x0000000000000002UL;
            constexpr const auto from = 1;
            constexpr const auto name = "pmc1";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace pmc2
        {
            constexpr const auto mask = 0x0000000000000004UL;
            constexpr const auto from = 2;
            constexpr const auto name = "pmc2";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace pmc3
        {
            constexpr const auto mask = 0x0000000000000008UL;
            constexpr const auto from = 3;
            constexpr const auto name = "pmc3";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace pmc4
        {
            constexpr const auto mask = 0x0000000000000010UL;
            constexpr const auto from = 4;
            constexpr const auto name = "pmc4";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace pmc5
        {
            constexpr const auto mask = 0x0000000000000020UL;
            constexpr const auto from = 5;
            constexpr const auto name = "pmc5";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace pmc6
        {
            constexpr const auto mask = 0x0000000000000040UL;
            constexpr const auto from = 6;
            constexpr const auto name = "pmc6";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace pmc7
        {
            constexpr const auto mask = 0x0000000000000080UL;
            constexpr const auto from = 7;
            constexpr const auto name = "pmc7";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace fixed_ctr0
        {
            constexpr const auto mask = 0x0000000100000000UL;
            constexpr const auto from = 32;
            constexpr const auto name = "fixed_ctr0";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace fixed_ctr1
        {
            constexpr const auto mask = 0x0000000200000000UL;
            constexpr const auto from = 33;
            constexpr const auto name = "fixed_ctr1";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace fixed_ctr2
        {
            constexpr const auto mask = 0x0000000400000000UL;
            constexpr const auto from = 34;
            constexpr const auto name = "fixed_ctr2";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        inline void dump() noexcept
        {
            bfdebug << "msrs::ia32_perf_global_ctrl enabled flags:" << bfendl;

            if (pmc0::get())
                bfdebug << "    - " << pmc0::name << bfendl;
            if (pmc1::get())
                bfdebug << "    - " << pmc1::name << bfendl;
            if (pmc2::get())
                bfdebug << "    - " << pmc2::name << bfendl;
            if (pmc3::get())
                bfdebug << "    - " << pmc3::name << bfendl;
            if (pmc4::get())
                bfdebug << "    - " << pmc4::name << bfendl;
            if (pmc5::get())
                bfdebug << "    - " << pmc5::name << bfendl;
            if (pmc6::get())
                bfdebug << "    - " << pmc6::name << bfendl;
            if (pmc7::get())
                bfdebug << "    - " << pmc7::name << bfendl;
            if (fixed_ctr0::get())
                bfdebug << "    - " << fixed_ctr0::name << bfendl;
            if (fixed_ctr1::get())
                bfdebug << "    - " << fixed_ctr1::name << bfendl;
            if (fixed_ctr2::get())
                bfdebug << "    - " << fixed_ctr2::name << bfendl;
        }
    }

    namespace ia32_vmx_basic
    {
        constexpr const auto addr = 0x00000480U;
        constexpr const auto name = "ia32_vmx_basic";

        inline auto get() noexcept
        { return __read_msr(addr); }

        namespace revision_id
        {
            constexpr const auto mask = 0x000000007FFFFFFFUL;
            constexpr const auto from = 0;
            constexpr const auto name = "revision_id";

            inline auto get() noexcept
            { return get_bits(__read_msr(addr), mask) >> from; }
        }

        namespace vmxon_vmcs_region_size
        {
            constexpr const auto mask = 0x00001FFF00000000UL;
            constexpr const auto from = 32;
            constexpr const auto name = "vmxon_vmcs_region_size";

            inline auto get() noexcept
            { return get_bits(__read_msr(addr), mask) >> from; }
        }

        namespace physical_address_width
        {
            constexpr const auto mask = 0x0001000000000000UL;
            constexpr const auto from = 48;
            constexpr const auto name = "physical_address_width";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        namespace dual_monitor_mode_support
        {
            constexpr const auto mask = 0x0002000000000000UL;
            constexpr const auto from = 49;
            constexpr const auto name = "dual_monitor_mode_support";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        namespace memory_type
        {
            constexpr const auto mask = 0x003C000000000000UL;
            constexpr const auto from = 50;
            constexpr const auto name = "memory_type";

            inline auto get() noexcept
            { return get_bits(__read_msr(addr), mask) >> from; }
        }

        namespace ins_outs_exit_information
        {
            constexpr const auto mask = 0x0040000000000000UL;
            constexpr const auto from = 54;
            constexpr const auto name = "ins_outs_exit_information";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        namespace true_based_controls
        {
            constexpr const auto mask = 0x0080000000000000UL;
            constexpr const auto from = 55;
            constexpr const auto name = "true_based_controls";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        inline void dump() noexcept
        {
            bfdebug << "msrs::ia32_vmx_basic enabled flags:" << bfendl;

            if (physical_address_width::get())
                bfdebug << "    - " << physical_address_width::name << bfendl;
            if (dual_monitor_mode_support::get())
                bfdebug << "    - " << dual_monitor_mode_support::name << bfendl;
            if (ins_outs_exit_information::get())
                bfdebug << "    - " << ins_outs_exit_information::name << bfendl;
            if (true_based_controls::get())
                bfdebug << "    - " << true_based_controls::name << bfendl;

            bfdebug << bfendl;
            bfdebug << "msrs::ia32_vmx_basic fields:" << bfendl;

            bfdebug << "    - " << revision_id::name << " = "
                    << view_as_pointer(revision_id::get()) << bfendl;
            bfdebug << "    - " << vmxon_vmcs_region_size::name << " = "
                    << view_as_pointer(vmxon_vmcs_region_size::get()) << bfendl;
            bfdebug << "    - " << memory_type::name << " = "
                    << view_as_pointer(memory_type::get()) << bfendl;
        }
    }

    namespace ia32_vmx_misc
    {
        constexpr const auto addr = 0x00000485U;
        constexpr const auto name = "ia32_vmx_misc";

        inline auto get() noexcept
        { return __read_msr(addr); }

        namespace preemption_timer_decrement
        {
            constexpr const auto mask = 0x000000000000001FUL;
            constexpr const auto from = 0;
            constexpr const auto name = "preemption_timer_decrement";

            inline auto get() noexcept
            { return get_bits(__read_msr(addr), mask) >> from; }
        }

        namespace store_efer_lma_on_vm_exit
        {
            constexpr const auto mask = 0x0000000000000020UL;
            constexpr const auto from = 5;
            constexpr const auto name = "store_efer_lma_on_vm_exit";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        namespace activity_state_hlt_support
        {
            constexpr const auto mask = 0x0000000000000040UL;
            constexpr const auto from = 6;
            constexpr const auto name = "activity_state_hlt_support";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        namespace activity_state_shutdown_support
        {
            constexpr const auto mask = 0x0000000000000080UL;
            constexpr const auto from = 7;
            constexpr const auto name = "activity_state_shutdown_support";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        namespace activity_state_wait_for_sipi_support
        {
            constexpr const auto mask = 0x0000000000000100UL;
            constexpr const auto from = 8;
            constexpr const auto name = "activity_state_wait_for_sipi_support";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        namespace processor_trace_support
        {
            constexpr const auto mask = 0x0000000000004000UL;
            constexpr const auto from = 14;
            constexpr const auto name = "processor_trace_support";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        namespace rdmsr_in_smm_support
        {
            constexpr const auto mask = 0x0000000000008000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "rdmsr_in_smm_support";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        namespace cr3_targets
        {
            constexpr const auto mask = 0x0000000001FF0000UL;
            constexpr const auto from = 16;
            constexpr const auto name = "cr3_targets";

            inline auto get() noexcept
            { return get_bits(__read_msr(addr), mask) >> from; }
        }

        namespace max_num_msr_load_store_on_exit
        {
            constexpr const auto mask = 0x000000000E000000UL;
            constexpr const auto from = 25;
            constexpr const auto name = "max_num_msr_load_store_on_exit";

            inline auto get() noexcept
            { return get_bits(__read_msr(addr), mask) >> from; }
        }

        namespace vmxoff_blocked_smi_support
        {
            constexpr const auto mask = 0x0000000010000000UL;
            constexpr const auto from = 28;
            constexpr const auto name = "vmxoff_blocked_smi_support";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        namespace vmwrite_all_fields_support
        {
            constexpr const auto mask = 0x0000000020000000UL;
            constexpr const auto from = 29;
            constexpr const auto name = "vmwrite_all_fields_support";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        namespace injection_with_instruction_length_of_zero
        {
            constexpr const auto mask = 0x0000000040000000UL;
            constexpr const auto from = 30;
            constexpr const auto name = "injection_with_instruction_length_of_zero";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        inline void dump() noexcept
        {
            bfdebug << "msrs::ia32_vmx_misc enabled flags:" << bfendl;

            if (store_efer_lma_on_vm_exit::get())
                bfdebug << "    - " << store_efer_lma_on_vm_exit::name << bfendl;
            if (activity_state_hlt_support::get())
                bfdebug << "    - " << activity_state_hlt_support::name << bfendl;
            if (activity_state_shutdown_support::get())
                bfdebug << "    - " << activity_state_shutdown_support::name << bfendl;
            if (activity_state_wait_for_sipi_support::get())
                bfdebug << "    - " << activity_state_wait_for_sipi_support::name << bfendl;
            if (processor_trace_support::get())
                bfdebug << "    - " << processor_trace_support::name << bfendl;
            if (rdmsr_in_smm_support::get())
                bfdebug << "    - " << rdmsr_in_smm_support::name << bfendl;
            if (vmxoff_blocked_smi_support::get())
                bfdebug << "    - " << vmxoff_blocked_smi_support::name << bfendl;
            if (vmwrite_all_fields_support::get())
                bfdebug << "    - " << vmwrite_all_fields_support::name << bfendl;
            if (injection_with_instruction_length_of_zero::get())
                bfdebug << "    - " << injection_with_instruction_length_of_zero::name << bfendl;

            bfdebug << bfendl;
            bfdebug << "msrs::ia32_vmx_misc fields:" << bfendl;

            bfdebug << "    - " << preemption_timer_decrement::name << " = "
                    << view_as_pointer(preemption_timer_decrement::get()) << bfendl;
            bfdebug << "    - " << cr3_targets::name << " = "
                    << view_as_pointer(cr3_targets::get()) << bfendl;
            bfdebug << "    - " << max_num_msr_load_store_on_exit::name << " = "
                    << view_as_pointer(max_num_msr_load_store_on_exit::get()) << bfendl;
        }
    }

    namespace ia32_vmx_cr0_fixed0
    {
        constexpr const auto addr = 0x00000486U;
        constexpr const auto name = "ia32_vmx_cr0_fixed0";

        inline auto get() noexcept
        { return __read_msr(addr); }
    }

    namespace ia32_vmx_cr0_fixed1
    {
        constexpr const auto addr = 0x00000487U;
        constexpr const auto name = "ia32_vmx_cr0_fixed1";

        inline auto get() noexcept
        { return __read_msr(addr); }
    }

    namespace ia32_vmx_cr4_fixed0
    {
        constexpr const auto addr = 0x00000488U;
        constexpr const auto name = "ia32_vmx_cr4_fixed0";

        inline auto get() noexcept
        { return __read_msr(addr); }
    }

    namespace ia32_vmx_cr4_fixed1
    {
        constexpr const auto addr = 0x00000489U;
        constexpr const auto name = "ia32_vmx_cr4_fixed1";

        inline auto get() noexcept
        { return __read_msr(addr); }
    }

    namespace ia32_vmx_procbased_ctls2
    {
        constexpr const auto addr = 0x0000048BU;
        constexpr const auto name = "ia32_vmx_procbased_ctls2";

        inline auto get() noexcept
        { return __read_msr(addr); }

        inline auto allowed0()
        { return (__read_msr(addr) & 0x00000000FFFFFFFFUL); }

        inline auto allowed1()
        { return ((__read_msr(addr) & 0xFFFFFFFF00000000UL) >> 32); }

        namespace virtualize_apic_accesses
        {
            constexpr const auto mask = 0x0000000000000001UL;
            constexpr const auto from = 0;
            constexpr const auto name = "virtualize_apic_accesses";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace enable_ept
        {
            constexpr const auto mask = 0x0000000000000002UL;
            constexpr const auto from = 1;
            constexpr const auto name = "enable_ept";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace descriptor_table_exiting
        {
            constexpr const auto mask = 0x0000000000000004UL;
            constexpr const auto from = 2;
            constexpr const auto name = "descriptor_table_exiting";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace enable_rdtscp
        {
            constexpr const auto mask = 0x0000000000000008UL;
            constexpr const auto from = 3;
            constexpr const auto name = "enable_rdtscp";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace virtualize_x2apic_mode
        {
            constexpr const auto mask = 0x0000000000000010UL;
            constexpr const auto from = 4;
            constexpr const auto name = "virtualize_x2apic_mode";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace enable_vpid
        {
            constexpr const auto mask = 0x0000000000000020UL;
            constexpr const auto from = 5;
            constexpr const auto name = "enable_vpid";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace wbinvd_exiting
        {
            constexpr const auto mask = 0x0000000000000040UL;
            constexpr const auto from = 6;
            constexpr const auto name = "wbinvd_exiting";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace unrestricted_guest
        {
            constexpr const auto mask = 0x0000000000000080UL;
            constexpr const auto from = 7;
            constexpr const auto name = "unrestricted_guest";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace apic_register_virtualization
        {
            constexpr const auto mask = 0x0000000000000100UL;
            constexpr const auto from = 8;
            constexpr const auto name = "apic_register_virtualization";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace virtual_interrupt_delivery
        {
            constexpr const auto mask = 0x0000000000000200UL;
            constexpr const auto from = 9;
            constexpr const auto name = "virtual_interrupt_delivery";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace pause_loop_exiting
        {
            constexpr const auto mask = 0x0000000000000400UL;
            constexpr const auto from = 10;
            constexpr const auto name = "pause_loop_exiting";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace rdrand_exiting
        {
            constexpr const auto mask = 0x0000000000000800UL;
            constexpr const auto from = 11;
            constexpr const auto name = "rdrand_exiting";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace enable_invpcid
        {
            constexpr const auto mask = 0x0000000000001000UL;
            constexpr const auto from = 12;
            constexpr const auto name = "enable_invpcid";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace enable_vm_functions
        {
            constexpr const auto mask = 0x0000000000002000UL;
            constexpr const auto from = 13;
            constexpr const auto name = "enable_vm_functions";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace vmcs_shadowing
        {
            constexpr const auto mask = 0x0000000000004000UL;
            constexpr const auto from = 14;
            constexpr const auto name = "vmcs_shadowing";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace rdseed_exiting
        {
            constexpr const auto mask = 0x0000000000010000UL;
            constexpr const auto from = 16;
            constexpr const auto name = "rdseed_exiting";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace enable_pml
        {
            constexpr const auto mask = 0x0000000000020000UL;
            constexpr const auto from = 17;
            constexpr const auto name = "enable_pml";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace ept_violation_ve
        {
            constexpr const auto mask = 0x0000000000040000UL;
            constexpr const auto from = 18;
            constexpr const auto name = "ept_violation_ve";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace enable_xsaves_xrstors
        {
            constexpr const auto mask = 0x0000000000100000UL;
            constexpr const auto from = 20;
            constexpr const auto name = "enable_xsaves_xrstors";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        inline void dump() noexcept
        {
            bfdebug << "msrs::ia32_vmx_procbased_ctls2 enabled flags:" << bfendl;

            if (virtualize_apic_accesses::get())
                bfdebug << "    - " << virtualize_apic_accesses::name << bfendl;
            if (enable_ept::get())
                bfdebug << "    - " << enable_ept::name << bfendl;
            if (descriptor_table_exiting::get())
                bfdebug << "    - " << descriptor_table_exiting::name << bfendl;
            if (enable_rdtscp::get())
                bfdebug << "    - " << enable_rdtscp::name << bfendl;
            if (virtualize_x2apic_mode::get())
                bfdebug << "    - " << virtualize_x2apic_mode::name << bfendl;
            if (enable_vpid::get())
                bfdebug << "    - " << enable_vpid::name << bfendl;
            if (wbinvd_exiting::get())
                bfdebug << "    - " << wbinvd_exiting::name << bfendl;
            if (unrestricted_guest::get())
                bfdebug << "    - " << unrestricted_guest::name << bfendl;
            if (apic_register_virtualization::get())
                bfdebug << "    - " << apic_register_virtualization::name << bfendl;
            if (virtual_interrupt_delivery::get())
                bfdebug << "    - " << virtual_interrupt_delivery::name << bfendl;
            if (pause_loop_exiting::get())
                bfdebug << "    - " << pause_loop_exiting::name << bfendl;
            if (rdrand_exiting::get())
                bfdebug << "    - " << rdrand_exiting::name << bfendl;
            if (enable_invpcid::get())
                bfdebug << "    - " << enable_invpcid::name << bfendl;
            if (enable_vm_functions::get())
                bfdebug << "    - " << enable_vm_functions::name << bfendl;
            if (vmcs_shadowing::get())
                bfdebug << "    - " << vmcs_shadowing::name << bfendl;
            if (rdseed_exiting::get())
                bfdebug << "    - " << rdseed_exiting::name << bfendl;
            if (enable_pml::get())
                bfdebug << "    - " << enable_pml::name << bfendl;
            if (ept_violation_ve::get())
                bfdebug << "    - " << ept_violation_ve::name << bfendl;
            if (enable_xsaves_xrstors::get())
                bfdebug << "    - " << enable_xsaves_xrstors::name << bfendl;

            bfdebug << bfendl;
            bfdebug << "msrs::ia32_vmx_procbased_ctls2 allowed0 fields:" << bfendl;

            if (virtualize_apic_accesses::is_allowed0())
                bfdebug << "    - " << virtualize_apic_accesses::name << bfendl;
            if (enable_ept::is_allowed0())
                bfdebug << "    - " << enable_ept::name << bfendl;
            if (descriptor_table_exiting::is_allowed0())
                bfdebug << "    - " << descriptor_table_exiting::name << bfendl;
            if (enable_rdtscp::is_allowed0())
                bfdebug << "    - " << enable_rdtscp::name << bfendl;
            if (virtualize_x2apic_mode::is_allowed0())
                bfdebug << "    - " << virtualize_x2apic_mode::name << bfendl;
            if (enable_vpid::is_allowed0())
                bfdebug << "    - " << enable_vpid::name << bfendl;
            if (wbinvd_exiting::is_allowed0())
                bfdebug << "    - " << wbinvd_exiting::name << bfendl;
            if (unrestricted_guest::is_allowed0())
                bfdebug << "    - " << unrestricted_guest::name << bfendl;
            if (apic_register_virtualization::is_allowed0())
                bfdebug << "    - " << apic_register_virtualization::name << bfendl;
            if (virtual_interrupt_delivery::is_allowed0())
                bfdebug << "    - " << virtual_interrupt_delivery::name << bfendl;
            if (pause_loop_exiting::is_allowed0())
                bfdebug << "    - " << pause_loop_exiting::name << bfendl;
            if (rdrand_exiting::is_allowed0())
                bfdebug << "    - " << rdrand_exiting::name << bfendl;
            if (enable_invpcid::is_allowed0())
                bfdebug << "    - " << enable_invpcid::name << bfendl;
            if (enable_vm_functions::is_allowed0())
                bfdebug << "    - " << enable_vm_functions::name << bfendl;
            if (vmcs_shadowing::is_allowed0())
                bfdebug << "    - " << vmcs_shadowing::name << bfendl;
            if (rdseed_exiting::is_allowed0())
                bfdebug << "    - " << rdseed_exiting::name << bfendl;
            if (enable_pml::is_allowed0())
                bfdebug << "    - " << enable_pml::name << bfendl;
            if (ept_violation_ve::is_allowed0())
                bfdebug << "    - " << ept_violation_ve::name << bfendl;
            if (enable_xsaves_xrstors::is_allowed0())
                bfdebug << "    - " << enable_xsaves_xrstors::name << bfendl;

            bfdebug << bfendl;
            bfdebug << "msrs::ia32_vmx_procbased_ctls2 allowed1 fields:" << bfendl;

            if (virtualize_apic_accesses::is_allowed1())
                bfdebug << "    - " << virtualize_apic_accesses::name << bfendl;
            if (enable_ept::is_allowed1())
                bfdebug << "    - " << enable_ept::name << bfendl;
            if (descriptor_table_exiting::is_allowed1())
                bfdebug << "    - " << descriptor_table_exiting::name << bfendl;
            if (enable_rdtscp::is_allowed1())
                bfdebug << "    - " << enable_rdtscp::name << bfendl;
            if (virtualize_x2apic_mode::is_allowed1())
                bfdebug << "    - " << virtualize_x2apic_mode::name << bfendl;
            if (enable_vpid::is_allowed1())
                bfdebug << "    - " << enable_vpid::name << bfendl;
            if (wbinvd_exiting::is_allowed1())
                bfdebug << "    - " << wbinvd_exiting::name << bfendl;
            if (unrestricted_guest::is_allowed1())
                bfdebug << "    - " << unrestricted_guest::name << bfendl;
            if (apic_register_virtualization::is_allowed1())
                bfdebug << "    - " << apic_register_virtualization::name << bfendl;
            if (virtual_interrupt_delivery::is_allowed1())
                bfdebug << "    - " << virtual_interrupt_delivery::name << bfendl;
            if (pause_loop_exiting::is_allowed1())
                bfdebug << "    - " << pause_loop_exiting::name << bfendl;
            if (rdrand_exiting::is_allowed1())
                bfdebug << "    - " << rdrand_exiting::name << bfendl;
            if (enable_invpcid::is_allowed1())
                bfdebug << "    - " << enable_invpcid::name << bfendl;
            if (enable_vm_functions::is_allowed1())
                bfdebug << "    - " << enable_vm_functions::name << bfendl;
            if (vmcs_shadowing::is_allowed1())
                bfdebug << "    - " << vmcs_shadowing::name << bfendl;
            if (rdseed_exiting::is_allowed1())
                bfdebug << "    - " << rdseed_exiting::name << bfendl;
            if (enable_pml::is_allowed1())
                bfdebug << "    - " << enable_pml::name << bfendl;
            if (ept_violation_ve::is_allowed1())
                bfdebug << "    - " << ept_violation_ve::name << bfendl;
            if (enable_xsaves_xrstors::is_allowed1())
                bfdebug << "    - " << enable_xsaves_xrstors::name << bfendl;
        }
    }

    namespace ia32_vmx_ept_vpid_cap
    {
        constexpr const auto addr = 0x0000048CU;
        constexpr const auto name = "ia32_vmx_ept_vpid_cap";

        inline auto get() noexcept
        { return __read_msr(addr); }

        namespace execute_only_translation
        {
            constexpr const auto mask = 0x0000000000000001UL;
            constexpr const auto from = 0;
            constexpr const auto name = "execute_only_translation";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        namespace page_walk_length_of_4
        {
            constexpr const auto mask = 0x0000000000000040UL;
            constexpr const auto from = 6;
            constexpr const auto name = "page_walk_length_of_4";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        namespace memory_type_uncacheable_supported
        {
            constexpr const auto mask = 0x0000000000000100UL;
            constexpr const auto from = 8;
            constexpr const auto name = "memory_type_uncacheable_supported";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        namespace memory_type_write_back_supported
        {
            constexpr const auto mask = 0x0000000000004000UL;
            constexpr const auto from = 14;
            constexpr const auto name = "memory_type_write_back_supported";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        namespace pde_2mb_support
        {
            constexpr const auto mask = 0x0000000000010000UL;
            constexpr const auto from = 16;
            constexpr const auto name = "pde_2mb_support";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        namespace pdpte_1mb_support
        {
            constexpr const auto mask = 0x0000000000020000UL;
            constexpr const auto from = 17;
            constexpr const auto name = "pdpte_1mb_support";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        namespace invept_support
        {
            constexpr const auto mask = 0x0000000000100000UL;
            constexpr const auto from = 20;
            constexpr const auto name = "invept_support";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        namespace accessed_dirty_support
        {
            constexpr const auto mask = 0x0000000000200000UL;
            constexpr const auto from = 21;
            constexpr const auto name = "accessed_dirty_support";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        namespace invept_single_context_support
        {
            constexpr const auto mask = 0x0000000002000000UL;
            constexpr const auto from = 25;
            constexpr const auto name = "invept_single_context_support";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        namespace invept_all_context_support
        {
            constexpr const auto mask = 0x0000000004000000UL;
            constexpr const auto from = 26;
            constexpr const auto name = "invept_all_context_support";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        namespace invvpid_support
        {
            constexpr const auto mask = 0x0000000100000000UL;
            constexpr const auto from = 32;
            constexpr const auto name = "invvpid_support";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        namespace invvpid_individual_address_support
        {
            constexpr const auto mask = 0x0000010000000000UL;
            constexpr const auto from = 40;
            constexpr const auto name = "invvpid_individual_address_support";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        namespace invvpid_single_context_support
        {
            constexpr const auto mask = 0x0000020000000000UL;
            constexpr const auto from = 41;
            constexpr const auto name = "invvpid_single_context_support";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        namespace invvpid_all_context_support
        {
            constexpr const auto mask = 0x0000040000000000UL;
            constexpr const auto from = 42;
            constexpr const auto name = "invvpid_all_context_support";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        namespace invvpid_single_context_retaining_globals_support
        {
            constexpr const auto mask = 0x0000080000000000UL;
            constexpr const auto from = 43;
            constexpr const auto name = "invvpid_single_context_retaining_globals_support";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }
        }

        inline void dump() noexcept
        {
            bfdebug << "msrs::ia32_vmx_ept_vpid_cap enabled flags:" << bfendl;

            if (execute_only_translation::get())
                bfdebug << "    - " << execute_only_translation::name << bfendl;
            if (page_walk_length_of_4::get())
                bfdebug << "    - " << page_walk_length_of_4::name << bfendl;
            if (memory_type_uncacheable_supported::get())
                bfdebug << "    - " << memory_type_uncacheable_supported::name << bfendl;
            if (memory_type_write_back_supported::get())
                bfdebug << "    - " << memory_type_write_back_supported::name << bfendl;
            if (pde_2mb_support::get())
                bfdebug << "    - " << pde_2mb_support::name << bfendl;
            if (pdpte_1mb_support::get())
                bfdebug << "    - " << pdpte_1mb_support::name << bfendl;
            if (invept_support::get())
                bfdebug << "    - " << invept_support::name << bfendl;
            if (accessed_dirty_support::get())
                bfdebug << "    - " << accessed_dirty_support::name << bfendl;
            if (invept_single_context_support::get())
                bfdebug << "    - " << invept_single_context_support::name << bfendl;
            if (invept_all_context_support::get())
                bfdebug << "    - " << invept_all_context_support::name << bfendl;
            if (invvpid_support::get())
                bfdebug << "    - " << invvpid_support::name << bfendl;
            if (invvpid_individual_address_support::get())
                bfdebug << "    - " << invvpid_individual_address_support::name << bfendl;
            if (invvpid_single_context_support::get())
                bfdebug << "    - " << invvpid_single_context_support::name << bfendl;
            if (invvpid_all_context_support::get())
                bfdebug << "    - " << invvpid_all_context_support::name << bfendl;
            if (invvpid_single_context_retaining_globals_support::get())
                bfdebug << "    - " << invvpid_single_context_retaining_globals_support::name << bfendl;
        }
    }

    namespace ia32_vmx_true_pinbased_ctls
    {
        constexpr const auto addr = 0x0000048DU;
        constexpr const auto name = "ia32_vmx_true_pinbased_ctls";

        inline auto get() noexcept
        { return __read_msr(addr); }

        inline auto allowed0()
        { return (__read_msr(addr) & 0x00000000FFFFFFFFUL); }

        inline auto allowed1()
        { return ((__read_msr(addr) & 0xFFFFFFFF00000000UL) >> 32); }

        namespace external_interrupt_exiting
        {
            constexpr const auto mask = 0x0000000000000001UL;
            constexpr const auto from = 0;
            constexpr const auto name = "external_interrupt_exiting";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace nmi_exiting
        {
            constexpr const auto mask = 0x0000000000000008UL;
            constexpr const auto from = 3;
            constexpr const auto name = "nmi_exiting";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace virtual_nmis
        {
            constexpr const auto mask = 0x0000000000000020UL;
            constexpr const auto from = 5;
            constexpr const auto name = "virtual_nmis";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace activate_vmx_preemption_timer
        {
            constexpr const auto mask = 0x0000000000000040UL;
            constexpr const auto from = 6;
            constexpr const auto name = "activate_vmx_preemption_timer";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace process_posted_interrupts
        {
            constexpr const auto mask = 0x0000000000000080UL;
            constexpr const auto from = 7;
            constexpr const auto name = "process_posted_interrupts";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        inline void dump() noexcept
        {
            bfdebug << "msrs::ia32_vmx_true_pinbased_ctls enabled flags:" << bfendl;

            if (external_interrupt_exiting::get())
                bfdebug << "    - " << external_interrupt_exiting::name << bfendl;
            if (nmi_exiting::get())
                bfdebug << "    - " << nmi_exiting::name << bfendl;
            if (virtual_nmis::get())
                bfdebug << "    - " << virtual_nmis::name << bfendl;
            if (activate_vmx_preemption_timer::get())
                bfdebug << "    - " << activate_vmx_preemption_timer::name << bfendl;
            if (process_posted_interrupts::get())
                bfdebug << "    - " << process_posted_interrupts::name << bfendl;

            bfdebug << bfendl;
            bfdebug << "msrs::ia32_vmx_true_pinbased_ctls allowed0 fields:" << bfendl;

            if (external_interrupt_exiting::is_allowed0())
                bfdebug << "    - " << external_interrupt_exiting::name << bfendl;
            if (nmi_exiting::is_allowed0())
                bfdebug << "    - " << nmi_exiting::name << bfendl;
            if (virtual_nmis::is_allowed0())
                bfdebug << "    - " << virtual_nmis::name << bfendl;
            if (activate_vmx_preemption_timer::is_allowed0())
                bfdebug << "    - " << activate_vmx_preemption_timer::name << bfendl;
            if (process_posted_interrupts::is_allowed0())
                bfdebug << "    - " << process_posted_interrupts::name << bfendl;

            bfdebug << bfendl;
            bfdebug << "msrs::ia32_vmx_true_pinbased_ctls allowed1 fields:" << bfendl;

            if (external_interrupt_exiting::is_allowed1())
                bfdebug << "    - " << external_interrupt_exiting::name << bfendl;
            if (nmi_exiting::is_allowed1())
                bfdebug << "    - " << nmi_exiting::name << bfendl;
            if (virtual_nmis::is_allowed1())
                bfdebug << "    - " << virtual_nmis::name << bfendl;
            if (activate_vmx_preemption_timer::is_allowed1())
                bfdebug << "    - " << activate_vmx_preemption_timer::name << bfendl;
            if (process_posted_interrupts::is_allowed1())
                bfdebug << "    - " << process_posted_interrupts::name << bfendl;
        }
    }

    namespace ia32_vmx_true_procbased_ctls
    {
        constexpr const auto addr = 0x0000048EU;
        constexpr const auto name = "ia32_vmx_true_procbased_ctls";

        inline auto get() noexcept
        { return __read_msr(addr); }

        inline auto allowed0()
        { return (__read_msr(addr) & 0x00000000FFFFFFFFUL); }

        inline auto allowed1()
        { return ((__read_msr(addr) & 0xFFFFFFFF00000000UL) >> 32); }

        namespace interrupt_window_exiting
        {
            constexpr const auto mask = 0x0000000000000004UL;
            constexpr const auto from = 2;
            constexpr const auto name = "interrupt_window_exiting";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace use_tsc_offsetting
        {
            constexpr const auto mask = 0x0000000000000008UL;
            constexpr const auto from = 3;
            constexpr const auto name = "use_tsc_offsetting";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace hlt_exiting
        {
            constexpr const auto mask = 0x0000000000000080UL;
            constexpr const auto from = 7;
            constexpr const auto name = "hlt_exiting";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace invlpg_exiting
        {
            constexpr const auto mask = 0x0000000000000200UL;
            constexpr const auto from = 9;
            constexpr const auto name = "invlpg_exiting";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace mwait_exiting
        {
            constexpr const auto mask = 0x0000000000000400UL;
            constexpr const auto from = 10;
            constexpr const auto name = "mwait_exiting";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace rdpmc_exiting
        {
            constexpr const auto mask = 0x0000000000000800UL;
            constexpr const auto from = 11;
            constexpr const auto name = "rdpmc_exiting";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace rdtsc_exiting
        {
            constexpr const auto mask = 0x0000000000001000UL;
            constexpr const auto from = 12;
            constexpr const auto name = "rdtsc_exiting";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace cr3_load_exiting
        {
            constexpr const auto mask = 0x0000000000008000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "cr3_load_exiting";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace cr3_store_exiting
        {
            constexpr const auto mask = 0x0000000000010000UL;
            constexpr const auto from = 16;
            constexpr const auto name = "cr3_store_exiting";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace cr8_load_exiting
        {
            constexpr const auto mask = 0x0000000000080000UL;
            constexpr const auto from = 19;
            constexpr const auto name = "cr8_load_exiting";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace cr8_store_exiting
        {
            constexpr const auto mask = 0x0000000000100000UL;
            constexpr const auto from = 20;
            constexpr const auto name = "cr8_store_exiting";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace use_tpr_shadow
        {
            constexpr const auto mask = 0x0000000000200000UL;
            constexpr const auto from = 21;
            constexpr const auto name = "use_tpr_shadow";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace nmi_window_exiting
        {
            constexpr const auto mask = 0x0000000000400000UL;
            constexpr const auto from = 22;
            constexpr const auto name = "nmi_window_exiting";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace mov_dr_exiting
        {
            constexpr const auto mask = 0x0000000000800000UL;
            constexpr const auto from = 23;
            constexpr const auto name = "mov_dr_exiting";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace unconditional_io_exiting
        {
            constexpr const auto mask = 0x0000000001000000UL;
            constexpr const auto from = 24;
            constexpr const auto name = "unconditional_io_exiting";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace use_io_bitmaps
        {
            constexpr const auto mask = 0x0000000002000000UL;
            constexpr const auto from = 25;
            constexpr const auto name = "use_io_bitmaps";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace monitor_trap_flag
        {
            constexpr const auto mask = 0x0000000008000000UL;
            constexpr const auto from = 27;
            constexpr const auto name = "monitor_trap_flag";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace use_msr_bitmaps
        {
            constexpr const auto mask = 0x0000000010000000UL;
            constexpr const auto from = 28;
            constexpr const auto name = "use_msr_bitmaps";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace monitor_exiting
        {
            constexpr const auto mask = 0x0000000020000000UL;
            constexpr const auto from = 29;
            constexpr const auto name = "monitor_exiting";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace pause_exiting
        {
            constexpr const auto mask = 0x0000000040000000UL;
            constexpr const auto from = 30;
            constexpr const auto name = "pause_exiting";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace activate_secondary_controls
        {
            constexpr const auto mask = 0x0000000080000000UL;
            constexpr const auto from = 31;
            constexpr const auto name = "activate_secondary_controls";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        inline void dump() noexcept
        {
            bfdebug << "msrs::ia32_vmx_true_procbased_ctls enabled flags:" << bfendl;

            if (interrupt_window_exiting::get())
                bfdebug << "    - " << interrupt_window_exiting::name << bfendl;
            if (use_tsc_offsetting::get())
                bfdebug << "    - " << use_tsc_offsetting::name << bfendl;
            if (hlt_exiting::get())
                bfdebug << "    - " << hlt_exiting::name << bfendl;
            if (invlpg_exiting::get())
                bfdebug << "    - " << invlpg_exiting::name << bfendl;
            if (mwait_exiting::get())
                bfdebug << "    - " << mwait_exiting::name << bfendl;
            if (rdpmc_exiting::get())
                bfdebug << "    - " << rdpmc_exiting::name << bfendl;
            if (rdtsc_exiting::get())
                bfdebug << "    - " << rdtsc_exiting::name << bfendl;
            if (cr3_load_exiting::get())
                bfdebug << "    - " << cr3_load_exiting::name << bfendl;
            if (cr3_store_exiting::get())
                bfdebug << "    - " << cr3_store_exiting::name << bfendl;
            if (cr8_load_exiting::get())
                bfdebug << "    - " << cr8_load_exiting::name << bfendl;
            if (cr8_store_exiting::get())
                bfdebug << "    - " << cr8_store_exiting::name << bfendl;
            if (use_tpr_shadow::get())
                bfdebug << "    - " << use_tpr_shadow::name << bfendl;
            if (nmi_window_exiting::get())
                bfdebug << "    - " << nmi_window_exiting::name << bfendl;
            if (mov_dr_exiting::get())
                bfdebug << "    - " << mov_dr_exiting::name << bfendl;
            if (unconditional_io_exiting::get())
                bfdebug << "    - " << unconditional_io_exiting::name << bfendl;
            if (use_io_bitmaps::get())
                bfdebug << "    - " << use_io_bitmaps::name << bfendl;
            if (monitor_trap_flag::get())
                bfdebug << "    - " << monitor_trap_flag::name << bfendl;
            if (use_msr_bitmaps::get())
                bfdebug << "    - " << use_msr_bitmaps::name << bfendl;
            if (monitor_exiting::get())
                bfdebug << "    - " << monitor_exiting::name << bfendl;
            if (pause_exiting::get())
                bfdebug << "    - " << pause_exiting::name << bfendl;
            if (activate_secondary_controls::get())
                bfdebug << "    - " << activate_secondary_controls::name << bfendl;

            bfdebug << bfendl;
            bfdebug << "msrs::ia32_vmx_true_pinbased_ctls allowed0 fields:" << bfendl;

            if (interrupt_window_exiting::is_allowed0())
                bfdebug << "    - " << interrupt_window_exiting::name << bfendl;
            if (use_tsc_offsetting::is_allowed0())
                bfdebug << "    - " << use_tsc_offsetting::name << bfendl;
            if (hlt_exiting::is_allowed0())
                bfdebug << "    - " << hlt_exiting::name << bfendl;
            if (invlpg_exiting::is_allowed0())
                bfdebug << "    - " << invlpg_exiting::name << bfendl;
            if (mwait_exiting::is_allowed0())
                bfdebug << "    - " << mwait_exiting::name << bfendl;
            if (rdpmc_exiting::is_allowed0())
                bfdebug << "    - " << rdpmc_exiting::name << bfendl;
            if (rdtsc_exiting::is_allowed0())
                bfdebug << "    - " << rdtsc_exiting::name << bfendl;
            if (cr3_load_exiting::is_allowed0())
                bfdebug << "    - " << cr3_load_exiting::name << bfendl;
            if (cr3_store_exiting::is_allowed0())
                bfdebug << "    - " << cr3_store_exiting::name << bfendl;
            if (cr8_load_exiting::is_allowed0())
                bfdebug << "    - " << cr8_load_exiting::name << bfendl;
            if (cr8_store_exiting::is_allowed0())
                bfdebug << "    - " << cr8_store_exiting::name << bfendl;
            if (use_tpr_shadow::is_allowed0())
                bfdebug << "    - " << use_tpr_shadow::name << bfendl;
            if (nmi_window_exiting::is_allowed0())
                bfdebug << "    - " << nmi_window_exiting::name << bfendl;
            if (mov_dr_exiting::is_allowed0())
                bfdebug << "    - " << mov_dr_exiting::name << bfendl;
            if (unconditional_io_exiting::is_allowed0())
                bfdebug << "    - " << unconditional_io_exiting::name << bfendl;
            if (use_io_bitmaps::is_allowed0())
                bfdebug << "    - " << use_io_bitmaps::name << bfendl;
            if (monitor_trap_flag::is_allowed0())
                bfdebug << "    - " << monitor_trap_flag::name << bfendl;
            if (use_msr_bitmaps::is_allowed0())
                bfdebug << "    - " << use_msr_bitmaps::name << bfendl;
            if (monitor_exiting::is_allowed0())
                bfdebug << "    - " << monitor_exiting::name << bfendl;
            if (pause_exiting::is_allowed0())
                bfdebug << "    - " << pause_exiting::name << bfendl;
            if (activate_secondary_controls::is_allowed0())
                bfdebug << "    - " << activate_secondary_controls::name << bfendl;

            bfdebug << bfendl;
            bfdebug << "msrs::ia32_vmx_true_pinbased_ctls allowed1 fields:" << bfendl;

            if (interrupt_window_exiting::is_allowed1())
                bfdebug << "    - " << interrupt_window_exiting::name << bfendl;
            if (use_tsc_offsetting::is_allowed1())
                bfdebug << "    - " << use_tsc_offsetting::name << bfendl;
            if (hlt_exiting::is_allowed1())
                bfdebug << "    - " << hlt_exiting::name << bfendl;
            if (invlpg_exiting::is_allowed1())
                bfdebug << "    - " << invlpg_exiting::name << bfendl;
            if (mwait_exiting::is_allowed1())
                bfdebug << "    - " << mwait_exiting::name << bfendl;
            if (rdpmc_exiting::is_allowed1())
                bfdebug << "    - " << rdpmc_exiting::name << bfendl;
            if (rdtsc_exiting::is_allowed1())
                bfdebug << "    - " << rdtsc_exiting::name << bfendl;
            if (cr3_load_exiting::is_allowed1())
                bfdebug << "    - " << cr3_load_exiting::name << bfendl;
            if (cr3_store_exiting::is_allowed1())
                bfdebug << "    - " << cr3_store_exiting::name << bfendl;
            if (cr8_load_exiting::is_allowed1())
                bfdebug << "    - " << cr8_load_exiting::name << bfendl;
            if (cr8_store_exiting::is_allowed1())
                bfdebug << "    - " << cr8_store_exiting::name << bfendl;
            if (use_tpr_shadow::is_allowed1())
                bfdebug << "    - " << use_tpr_shadow::name << bfendl;
            if (nmi_window_exiting::is_allowed1())
                bfdebug << "    - " << nmi_window_exiting::name << bfendl;
            if (mov_dr_exiting::is_allowed1())
                bfdebug << "    - " << mov_dr_exiting::name << bfendl;
            if (unconditional_io_exiting::is_allowed1())
                bfdebug << "    - " << unconditional_io_exiting::name << bfendl;
            if (use_io_bitmaps::is_allowed1())
                bfdebug << "    - " << use_io_bitmaps::name << bfendl;
            if (monitor_trap_flag::is_allowed1())
                bfdebug << "    - " << monitor_trap_flag::name << bfendl;
            if (use_msr_bitmaps::is_allowed1())
                bfdebug << "    - " << use_msr_bitmaps::name << bfendl;
            if (monitor_exiting::is_allowed1())
                bfdebug << "    - " << monitor_exiting::name << bfendl;
            if (pause_exiting::is_allowed1())
                bfdebug << "    - " << pause_exiting::name << bfendl;
            if (activate_secondary_controls::is_allowed1())
                bfdebug << "    - " << activate_secondary_controls::name << bfendl;
        }
    }

    namespace ia32_vmx_true_exit_ctls
    {
        constexpr const auto addr = 0x0000048FU;
        constexpr const auto name = "ia32_vmx_true_exit_ctls";

        inline auto get() noexcept
        { return __read_msr(addr); }

        inline auto allowed0()
        { return (__read_msr(addr) & 0x00000000FFFFFFFFUL); }

        inline auto allowed1()
        { return ((__read_msr(addr) & 0xFFFFFFFF00000000UL) >> 32); }

        namespace save_debug_controls
        {
            constexpr const auto mask = 0x0000000000000004UL;
            constexpr const auto from = 2;
            constexpr const auto name = "save_debug_controls";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace host_address_space_size
        {
            constexpr const auto mask = 0x0000000000000200UL;
            constexpr const auto from = 9;
            constexpr const auto name = "host_address_space_size";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace load_ia32_perf_global_ctrl
        {
            constexpr const auto mask = 0x0000000000001000UL;
            constexpr const auto from = 12;
            constexpr const auto name = "load_ia32_perf_global_ctrl";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace acknowledge_interrupt_on_exit
        {
            constexpr const auto mask = 0x0000000000008000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "acknowledge_interrupt_on_exit";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace save_ia32_pat
        {
            constexpr const auto mask = 0x0000000000040000UL;
            constexpr const auto from = 18;
            constexpr const auto name = "save_ia32_pat";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace load_ia32_pat
        {
            constexpr const auto mask = 0x0000000000080000UL;
            constexpr const auto from = 19;
            constexpr const auto name = "load_ia32_pat";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace save_ia32_efer
        {
            constexpr const auto mask = 0x0000000000100000UL;
            constexpr const auto from = 20;
            constexpr const auto name = "save_ia32_efer";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace load_ia32_efer
        {
            constexpr const auto mask = 0x0000000000200000UL;
            constexpr const auto from = 21;
            constexpr const auto name = "load_ia32_efer";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace save_vmx_preemption_timer_value
        {
            constexpr const auto mask = 0x0000000000400000UL;
            constexpr const auto from = 22;
            constexpr const auto name = "save_vmx_preemption_timer_value";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        inline void dump() noexcept
        {
            bfdebug << "msrs::ia32_vmx_true_exit_ctls enabled flags:" << bfendl;

            if (save_debug_controls::get())
                bfdebug << "    - " << save_debug_controls::name << bfendl;
            if (host_address_space_size::get())
                bfdebug << "    - " << host_address_space_size::name << bfendl;
            if (load_ia32_perf_global_ctrl::get())
                bfdebug << "    - " << load_ia32_perf_global_ctrl::name << bfendl;
            if (acknowledge_interrupt_on_exit::get())
                bfdebug << "    - " << acknowledge_interrupt_on_exit::name << bfendl;
            if (save_ia32_pat::get())
                bfdebug << "    - " << save_ia32_pat::name << bfendl;
            if (load_ia32_pat::get())
                bfdebug << "    - " << load_ia32_pat::name << bfendl;
            if (save_ia32_efer::get())
                bfdebug << "    - " << save_ia32_efer::name << bfendl;
            if (load_ia32_efer::get())
                bfdebug << "    - " << load_ia32_efer::name << bfendl;
            if (save_vmx_preemption_timer_value::get())
                bfdebug << "    - " << save_vmx_preemption_timer_value::name << bfendl;

            bfdebug << bfendl;
            bfdebug << "msrs::ia32_vmx_true_exit_ctls allowed0 fields:" << bfendl;

            if (save_debug_controls::is_allowed0())
                bfdebug << "    - " << save_debug_controls::name << bfendl;
            if (host_address_space_size::is_allowed0())
                bfdebug << "    - " << host_address_space_size::name << bfendl;
            if (load_ia32_perf_global_ctrl::is_allowed0())
                bfdebug << "    - " << load_ia32_perf_global_ctrl::name << bfendl;
            if (acknowledge_interrupt_on_exit::is_allowed0())
                bfdebug << "    - " << acknowledge_interrupt_on_exit::name << bfendl;
            if (save_ia32_pat::is_allowed0())
                bfdebug << "    - " << save_ia32_pat::name << bfendl;
            if (load_ia32_pat::is_allowed0())
                bfdebug << "    - " << load_ia32_pat::name << bfendl;
            if (save_ia32_efer::is_allowed0())
                bfdebug << "    - " << save_ia32_efer::name << bfendl;
            if (load_ia32_efer::is_allowed0())
                bfdebug << "    - " << load_ia32_efer::name << bfendl;
            if (save_vmx_preemption_timer_value::is_allowed0())
                bfdebug << "    - " << save_vmx_preemption_timer_value::name << bfendl;

            bfdebug << bfendl;
            bfdebug << "msrs::ia32_vmx_true_exit_ctls allowed1 fields:" << bfendl;

            if (save_debug_controls::is_allowed1())
                bfdebug << "    - " << save_debug_controls::name << bfendl;
            if (host_address_space_size::is_allowed1())
                bfdebug << "    - " << host_address_space_size::name << bfendl;
            if (load_ia32_perf_global_ctrl::is_allowed1())
                bfdebug << "    - " << load_ia32_perf_global_ctrl::name << bfendl;
            if (acknowledge_interrupt_on_exit::is_allowed1())
                bfdebug << "    - " << acknowledge_interrupt_on_exit::name << bfendl;
            if (save_ia32_pat::is_allowed1())
                bfdebug << "    - " << save_ia32_pat::name << bfendl;
            if (load_ia32_pat::is_allowed1())
                bfdebug << "    - " << load_ia32_pat::name << bfendl;
            if (save_ia32_efer::is_allowed1())
                bfdebug << "    - " << save_ia32_efer::name << bfendl;
            if (load_ia32_efer::is_allowed1())
                bfdebug << "    - " << load_ia32_efer::name << bfendl;
            if (save_vmx_preemption_timer_value::is_allowed1())
                bfdebug << "    - " << save_vmx_preemption_timer_value::name << bfendl;
        }
    }

    namespace ia32_vmx_true_entry_ctls
    {
        constexpr const auto addr = 0x00000490U;
        constexpr const auto name = "ia32_vmx_true_entry_ctls";

        inline auto get() noexcept
        { return __read_msr(addr); }

        inline auto allowed0()
        { return (__read_msr(addr) & 0x00000000FFFFFFFFUL); }

        inline auto allowed1()
        { return ((__read_msr(addr) & 0xFFFFFFFF00000000UL) >> 32); }

        namespace load_debug_controls
        {
            constexpr const auto mask = 0x0000000000000004UL;
            constexpr const auto from = 2;
            constexpr const auto name = "load_debug_controls";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace ia_32e_mode_guest
        {
            constexpr const auto mask = 0x0000000000000200UL;
            constexpr const auto from = 9;
            constexpr const auto name = "ia_32e_mode_guest";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace entry_to_smm
        {
            constexpr const auto mask = 0x0000000000000400UL;
            constexpr const auto from = 10;
            constexpr const auto name = "entry_to_smm";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace deactivate_dual_monitor_treatment
        {
            constexpr const auto mask = 0x0000000000000800UL;
            constexpr const auto from = 11;
            constexpr const auto name = "deactivate_dual_monitor_treatment";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace load_ia32_perf_global_ctrl
        {
            constexpr const auto mask = 0x0000000000002000UL;
            constexpr const auto from = 13;
            constexpr const auto name = "load_ia32_perf_global_ctrl";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace load_ia32_pat
        {
            constexpr const auto mask = 0x0000000000004000UL;
            constexpr const auto from = 14;
            constexpr const auto name = "load_ia32_pat";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace load_ia32_efer
        {
            constexpr const auto mask = 0x0000000000008000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "load_ia32_efer";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (__read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (__read_msr(addr) & (mask << 32)) != 0; }
        }

        inline void dump() noexcept
        {
            bfdebug << "msrs::ia32_vmx_true_entry_ctls enabled flags:" << bfendl;

            if (load_debug_controls::get())
                bfdebug << "    - " << load_debug_controls::name << bfendl;
            if (ia_32e_mode_guest::get())
                bfdebug << "    - " << ia_32e_mode_guest::name << bfendl;
            if (entry_to_smm::get())
                bfdebug << "    - " << entry_to_smm::name << bfendl;
            if (deactivate_dual_monitor_treatment::get())
                bfdebug << "    - " << deactivate_dual_monitor_treatment::name << bfendl;
            if (load_ia32_perf_global_ctrl::get())
                bfdebug << "    - " << load_ia32_perf_global_ctrl::name << bfendl;
            if (load_ia32_pat::get())
                bfdebug << "    - " << load_ia32_pat::name << bfendl;
            if (load_ia32_efer::get())
                bfdebug << "    - " << load_ia32_efer::name << bfendl;

            bfdebug << bfendl;
            bfdebug << "msrs::ia32_vmx_true_entry_ctls allowed0 fields:" << bfendl;

            if (load_debug_controls::is_allowed0())
                bfdebug << "    - " << load_debug_controls::name << bfendl;
            if (ia_32e_mode_guest::is_allowed0())
                bfdebug << "    - " << ia_32e_mode_guest::name << bfendl;
            if (entry_to_smm::is_allowed0())
                bfdebug << "    - " << entry_to_smm::name << bfendl;
            if (deactivate_dual_monitor_treatment::is_allowed0())
                bfdebug << "    - " << deactivate_dual_monitor_treatment::name << bfendl;
            if (load_ia32_perf_global_ctrl::is_allowed0())
                bfdebug << "    - " << load_ia32_perf_global_ctrl::name << bfendl;
            if (load_ia32_pat::is_allowed0())
                bfdebug << "    - " << load_ia32_pat::name << bfendl;
            if (load_ia32_efer::is_allowed0())
                bfdebug << "    - " << load_ia32_efer::name << bfendl;

            bfdebug << bfendl;
            bfdebug << "msrs::ia32_vmx_true_entry_ctls allowed1 fields:" << bfendl;

            if (load_debug_controls::is_allowed1())
                bfdebug << "    - " << load_debug_controls::name << bfendl;
            if (ia_32e_mode_guest::is_allowed1())
                bfdebug << "    - " << ia_32e_mode_guest::name << bfendl;
            if (entry_to_smm::is_allowed1())
                bfdebug << "    - " << entry_to_smm::name << bfendl;
            if (deactivate_dual_monitor_treatment::is_allowed1())
                bfdebug << "    - " << deactivate_dual_monitor_treatment::name << bfendl;
            if (load_ia32_perf_global_ctrl::is_allowed1())
                bfdebug << "    - " << load_ia32_perf_global_ctrl::name << bfendl;
            if (load_ia32_pat::is_allowed1())
                bfdebug << "    - " << load_ia32_pat::name << bfendl;
            if (load_ia32_efer::is_allowed1())
                bfdebug << "    - " << load_ia32_efer::name << bfendl;
        }
    }

    namespace ia32_vmx_vmfunc
    {
        constexpr const auto addr = 0x00000491U;
        constexpr const auto name = "ia32_vmx_vmfunc";

        inline auto get() noexcept
        { return __read_msr(addr); }
    }

    namespace ia32_efer
    {
        constexpr const auto addr = 0xC0000080U;
        constexpr const auto name = "ia32_efer";

        inline auto get() noexcept
        { return __read_msr(addr); }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val) noexcept { __write_msr(addr, val); }

        namespace sce
        {
            constexpr const auto mask = 0x0000000000000001UL;
            constexpr const auto from = 0;
            constexpr const auto name = "sce";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace lme
        {
            constexpr const auto mask = 0x0000000000000100UL;
            constexpr const auto from = 8;
            constexpr const auto name = "lme";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace lma
        {
            constexpr const auto mask = 0x0000000000000400UL;
            constexpr const auto from = 10;
            constexpr const auto name = "lma";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace nxe
        {
            constexpr const auto mask = 0x0000000000000800UL;
            constexpr const auto from = 11;
            constexpr const auto name = "lma";

            inline auto get() noexcept
            { return get_bit(__read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { __write_msr(addr, val ? set_bit(__read_msr(addr), from) : clear_bit(__read_msr(addr), from)); }
        }

        namespace reserved
        {
            constexpr const auto mask = 0xFFFFFFFFFFFFF2FEUL;
            constexpr const auto from = 0;
            constexpr const auto name = "reserved";

            inline auto get() noexcept
            { return get_bits(__read_msr(addr), mask) >> from; }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set(T val) noexcept { __write_msr(addr, set_bits(__read_msr(addr), mask, val << from)); }
        }

        inline void dump() noexcept
        {
            bfdebug << "msrs::ia32_efer enabled flags:" << bfendl;

            if (sce::get())
                bfdebug << "    - " << sce::name << bfendl;
            if (lme::get())
                bfdebug << "    - " << lme::name << bfendl;
            if (lma::get())
                bfdebug << "    - " << lma::name << bfendl;
            if (nxe::get())
                bfdebug << "    - " << nxe::name << bfendl;
        }
    }

    namespace ia32_fs_base
    {
        constexpr const auto addr = 0xC0000100U;
        constexpr const auto name = "ia32_fs_base";

        inline auto get() noexcept
        { return __read_msr(addr); }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val) noexcept { __write_msr(addr, val); }
    }

    namespace ia32_gs_base
    {
        constexpr const auto addr = 0xC0000101U;
        constexpr const auto name = "ia32_gs_base";

        inline auto get() noexcept
        { return __read_msr(addr); }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val) noexcept { __write_msr(addr, val); }
    }
}
}

// *INDENT-ON*

#endif
