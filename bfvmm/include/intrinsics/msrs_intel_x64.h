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

extern "C" uint64_t __read_msr(uint32_t addr) noexcept;
extern "C" void __write_msr(uint32_t addr, uint64_t val) noexcept;

// *INDENT-OFF*

namespace intel_x64
{
namespace msrs
{
    template<class A> inline auto get(A addr) noexcept
    { return __read_msr(gsl::narrow_cast<uint32_t>(addr)); }

    template<class A, class T> void set(A addr, T val) noexcept
    { __write_msr(gsl::narrow_cast<uint32_t>(addr), val); }

    namespace ia32_feature_control
    {
        constexpr const auto addr = 0x0000003AU;
        constexpr const auto name = "ia32_feature_control";

        inline auto get() noexcept
        { return __read_msr(addr); }

        template<class T> void set(T val) noexcept
        { __write_msr(addr, val); }

        namespace lock_bit
        {
            constexpr const auto mask = 0x0000000000000001UL;
            constexpr const auto from = 0;
            constexpr const auto name = "lock_bit";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace enable_vmx_inside_smx
        {
            constexpr const auto mask = 0x0000000000000002UL;
            constexpr const auto from = 1;
            constexpr const auto name = "enable_vmx_inside_smx";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace enable_vmx_outside_smx
        {
            constexpr const auto mask = 0x0000000000000004UL;
            constexpr const auto from = 2;
            constexpr const auto name = "enable_vmx_outside_smx";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace senter_local_function_enables
        {
            constexpr const auto mask = 0x0000000000007F00UL;
            constexpr const auto from = 8;
            constexpr const auto name = "senter_local_function_enables";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace senter_gloabl_function_enable
        {
            constexpr const auto mask = 0x0000000000008000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "senter_gloabl_function_enables";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace sgx_launch_control_enable
        {
            constexpr const auto mask = 0x0000000000020000UL;
            constexpr const auto from = 17;
            constexpr const auto name = "sgx_launch_control_enable";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace sgx_global_enable
        {
            constexpr const auto mask = 0x0000000000040000UL;
            constexpr const auto from = 18;
            constexpr const auto name = "sgx_global_enable";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace lmce
        {
            constexpr const auto mask = 0x0000000000100000UL;
            constexpr const auto from = 20;
            constexpr const auto name = "lmce";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }
    }

    namespace ia32_sysenter_cs
    {
        constexpr const auto addr = 0x00000174U;
        constexpr const auto name = "ia32_sysenter_cs";

        inline auto get() noexcept
        { return __read_msr(addr); }

        template<class T> void set(T val) noexcept
        { __write_msr(addr, val); }
    }

    namespace ia32_sysenter_esp
    {
        constexpr const auto addr = 0x00000175U;
        constexpr const auto name = "ia32_sysenter_esp";

        inline auto get() noexcept
        { return __read_msr(addr); }

        template<class T> void set(T val) noexcept
        { __write_msr(addr, val); }
    }

    namespace ia32_sysenter_eip
    {
        constexpr const auto addr = 0x00000176;
        constexpr const auto name = "ia32_sysenter_eip";

        inline auto get() noexcept
        { return __read_msr(addr); }

        template<class T> void set(T val) noexcept
        { __write_msr(addr, val); }
    }

    namespace ia32_debugctl
    {
        constexpr const auto addr = 0x000001D9U;
        constexpr const auto name = "ia32_debugctl";

        inline auto get() noexcept
        { return __read_msr(addr); }

        template<class T> void set(T val) noexcept
        { __write_msr(addr, val); }

        namespace lbr
        {
            constexpr const auto mask = 0x0000000000000001UL;
            constexpr const auto from = 0;
            constexpr const auto name = "lbr";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace btf
        {
            constexpr const auto mask = 0x0000000000000002UL;
            constexpr const auto from = 1;
            constexpr const auto name = "btf";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace tr
        {
            constexpr const auto mask = 0x0000000000000040UL;
            constexpr const auto from = 6;
            constexpr const auto name = "tr";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace bts
        {
            constexpr const auto mask = 0x0000000000000080UL;
            constexpr const auto from = 7;
            constexpr const auto name = "bts";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace btint
        {
            constexpr const auto mask = 0x0000000000000100UL;
            constexpr const auto from = 8;
            constexpr const auto name = "btint";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace bt_off_os
        {
            constexpr const auto mask = 0x0000000000000200UL;
            constexpr const auto from = 9;
            constexpr const auto name = "bt_off_os";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace bt_off_user
        {
            constexpr const auto mask = 0x0000000000000400UL;
            constexpr const auto from = 10;
            constexpr const auto name = "bt_off_user";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace freeze_lbrs_on_pmi
        {
            constexpr const auto mask = 0x0000000000000800UL;
            constexpr const auto from = 11;
            constexpr const auto name = "freeze_lbrs_on_pmi";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace freeze_perfmon_on_pmi
        {
            constexpr const auto mask = 0x0000000000001000UL;
            constexpr const auto from = 12;
            constexpr const auto name = "freeze_perfmon_on_pmi";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace enable_uncore_pmi
        {
            constexpr const auto mask = 0x0000000000002000UL;
            constexpr const auto from = 13;
            constexpr const auto name = "enable_uncore_pmi";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace freeze_while_smm
        {
            constexpr const auto mask = 0x0000000000004000UL;
            constexpr const auto from = 14;
            constexpr const auto name = "freeze_while_smm";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace rtm_debug
        {
            constexpr const auto mask = 0x0000000000008000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "rtm_debug";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace reserved
        {
            constexpr const auto mask = 0xFFFFFFFFFFFF003CUL;
            constexpr const auto from = 0;
            constexpr const auto name = "reserved";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }
    }

    namespace ia32_pat
    {
        constexpr const auto addr = 0x00000277U;
        constexpr const auto name = "ia32_pat";

        inline auto get() noexcept
        { return __read_msr(addr); }

        template<class T> void set(T val) noexcept
        { __write_msr(addr, val); }

        namespace pa0
        {
            constexpr const auto mask = 0x0000000000000007UL;
            constexpr const auto from = 0;
            constexpr const auto name = "pa0";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace pa1
        {
            constexpr const auto mask = 0x0000000000000700UL;
            constexpr const auto from = 8;
            constexpr const auto name = "pa1";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace pa2
        {
            constexpr const auto mask = 0x0000000000070000UL;
            constexpr const auto from = 16;
            constexpr const auto name = "pa2";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace pa3
        {
            constexpr const auto mask = 0x0000000007000000UL;
            constexpr const auto from = 24;
            constexpr const auto name = "pa3";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace pa4
        {
            constexpr const auto mask = 0x0000000700000000UL;
            constexpr const auto from = 32;
            constexpr const auto name = "pa4";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace pa5
        {
            constexpr const auto mask = 0x0000070000000000UL;
            constexpr const auto from = 40;
            constexpr const auto name = "pa5";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace pa6
        {
            constexpr const auto mask = 0x0007000000000000UL;
            constexpr const auto from = 48;
            constexpr const auto name = "pa6";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace pa7
        {
            constexpr const auto mask = 0x0700000000000000UL;
            constexpr const auto from = 56;
            constexpr const auto name = "pa7";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }
    }

    namespace ia32_perf_global_ctrl
    {
        constexpr const auto addr = 0x0000038FU;
        constexpr const auto name = "ia32_perf_global_ctrl";

        inline auto get() noexcept
        { return __read_msr(addr); }

        template<class T> void set(T val) noexcept
        { __write_msr(addr, val); }

        namespace pmc0
        {
            constexpr const auto mask = 0x0000000000000001UL;
            constexpr const auto from = 0;
            constexpr const auto name = "pmc0";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace pmc1
        {
            constexpr const auto mask = 0x0000000000000002UL;
            constexpr const auto from = 1;
            constexpr const auto name = "pmc1";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace pmc2
        {
            constexpr const auto mask = 0x0000000000000004UL;
            constexpr const auto from = 2;
            constexpr const auto name = "pmc2";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace pmc3
        {
            constexpr const auto mask = 0x0000000000000008UL;
            constexpr const auto from = 3;
            constexpr const auto name = "pmc3";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace pmc4
        {
            constexpr const auto mask = 0x0000000000000010UL;
            constexpr const auto from = 4;
            constexpr const auto name = "pmc4";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace pmc5
        {
            constexpr const auto mask = 0x0000000000000020UL;
            constexpr const auto from = 5;
            constexpr const auto name = "pmc5";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace pmc6
        {
            constexpr const auto mask = 0x0000000000000040UL;
            constexpr const auto from = 6;
            constexpr const auto name = "pmc6";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace pmc7
        {
            constexpr const auto mask = 0x0000000000000080UL;
            constexpr const auto from = 7;
            constexpr const auto name = "pmc7";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace fixed_ctr0
        {
            constexpr const auto mask = 0x0000000100000000UL;
            constexpr const auto from = 32;
            constexpr const auto name = "fixed_ctr0";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace fixed_ctr1
        {
            constexpr const auto mask = 0x0000000200000000UL;
            constexpr const auto from = 33;
            constexpr const auto name = "fixed_ctr1";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace fixed_ctr2
        {
            constexpr const auto mask = 0x0000000400000000UL;
            constexpr const auto from = 34;
            constexpr const auto name = "fixed_ctr2";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
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
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace vmxon_vmcs_region_size
        {
            constexpr const auto mask = 0x00001FFF00000000UL;
            constexpr const auto from = 32;
            constexpr const auto name = "vmxon_vmcs_region_size";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace physical_address_width
        {
            constexpr const auto mask = 0x0001000000000000UL;
            constexpr const auto from = 48;
            constexpr const auto name = "physical_address_width";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace dual_monitor_mode_support
        {
            constexpr const auto mask = 0x0002000000000000UL;
            constexpr const auto from = 49;
            constexpr const auto name = "dual_monitor_mode_support";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace memory_type
        {
            constexpr const auto mask = 0x003C000000000000UL;
            constexpr const auto from = 50;
            constexpr const auto name = "memory_type";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace ins_outs_exit_information
        {
            constexpr const auto mask = 0x0040000000000000UL;
            constexpr const auto from = 54;
            constexpr const auto name = "ins_outs_exit_information";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace true_based_controls
        {
            constexpr const auto mask = 0x0080000000000000UL;
            constexpr const auto from = 55;
            constexpr const auto name = "true_based_controls";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
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
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace store_efer_lma_on_vm_exit
        {
            constexpr const auto mask = 0x0000000000000020UL;
            constexpr const auto from = 5;
            constexpr const auto name = "store_efer_lma_on_vm_exit";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace activity_state_hlt_support
        {
            constexpr const auto mask = 0x0000000000000040UL;
            constexpr const auto from = 6;
            constexpr const auto name = "activity_state_hlt_support";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace activity_state_shutdown_support
        {
            constexpr const auto mask = 0x0000000000000080UL;
            constexpr const auto from = 7;
            constexpr const auto name = "activity_state_shutdown_support";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace activity_state_wait_for_sipi_support
        {
            constexpr const auto mask = 0x0000000000000100UL;
            constexpr const auto from = 8;
            constexpr const auto name = "activity_state_wait_for_sipi_support";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace processor_trace_support
        {
            constexpr const auto mask = 0x0000000000004000UL;
            constexpr const auto from = 14;
            constexpr const auto name = "processor_trace_support";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace rdmsr_in_smm_support
        {
            constexpr const auto mask = 0x0000000000008000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "rdmsr_in_smm_support";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace cr3_targets
        {
            constexpr const auto mask = 0x0000000001FF0000UL;
            constexpr const auto from = 16;
            constexpr const auto name = "cr3_targets";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace max_num_msr_load_store_on_exit
        {
            constexpr const auto mask = 0x000000000E000000UL;
            constexpr const auto from = 25;
            constexpr const auto name = "max_num_msr_load_store_on_exit";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace vmxoff_blocked_smi_support
        {
            constexpr const auto mask = 0x0000000010000000UL;
            constexpr const auto from = 28;
            constexpr const auto name = "vmxoff_blocked_smi_support";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace vmwrite_all_fields_support
        {
            constexpr const auto mask = 0x0000000020000000UL;
            constexpr const auto from = 29;
            constexpr const auto name = "vmwrite_all_fields_support";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace injection_with_instruction_length_of_zero
        {
            constexpr const auto mask = 0x0000000040000000UL;
            constexpr const auto from = 30;
            constexpr const auto name = "injection_with_instruction_length_of_zero";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
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

        namespace virtualize_apic_accesses
        {
            constexpr const auto mask = 0x0000000000000001UL;
            constexpr const auto from = 0;
            constexpr const auto name = "virtualize_apic_accesses";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace enable_ept
        {
            constexpr const auto mask = 0x0000000000000002UL;
            constexpr const auto from = 1;
            constexpr const auto name = "enable_ept";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace descriptor_table_exiting
        {
            constexpr const auto mask = 0x0000000000000004UL;
            constexpr const auto from = 2;
            constexpr const auto name = "descriptor_table_exiting";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace enable_rdtscp
        {
            constexpr const auto mask = 0x0000000000000008UL;
            constexpr const auto from = 3;
            constexpr const auto name = "enable_rdtscp";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace virtualize_x2apic_mode
        {
            constexpr const auto mask = 0x0000000000000010UL;
            constexpr const auto from = 4;
            constexpr const auto name = "virtualize_x2apic_mode";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace enable_vpid
        {
            constexpr const auto mask = 0x0000000000000020UL;
            constexpr const auto from = 5;
            constexpr const auto name = "enable_vpid";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace wbinvd_exiting
        {
            constexpr const auto mask = 0x0000000000000040UL;
            constexpr const auto from = 6;
            constexpr const auto name = "wbinvd_exiting";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace unrestricted_guest
        {
            constexpr const auto mask = 0x0000000000000080UL;
            constexpr const auto from = 7;
            constexpr const auto name = "unrestricted_guest";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace apic_register_virtualization
        {
            constexpr const auto mask = 0x0000000000000100UL;
            constexpr const auto from = 8;
            constexpr const auto name = "apic_register_virtualization";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace virtual_interrupt_delivery
        {
            constexpr const auto mask = 0x0000000000000200UL;
            constexpr const auto from = 9;
            constexpr const auto name = "virtual_interrupt_delivery";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace pause_loop_exiting
        {
            constexpr const auto mask = 0x0000000000000400UL;
            constexpr const auto from = 10;
            constexpr const auto name = "pause_loop_exiting";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace rdrand_exiting
        {
            constexpr const auto mask = 0x0000000000000800UL;
            constexpr const auto from = 11;
            constexpr const auto name = "rdrand_exiting";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace enable_invpcid
        {
            constexpr const auto mask = 0x0000000000001000UL;
            constexpr const auto from = 12;
            constexpr const auto name = "enable_invpcid";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace enable_vm_functions
        {
            constexpr const auto mask = 0x0000000000002000UL;
            constexpr const auto from = 13;
            constexpr const auto name = "enable_vm_functions";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace vmcs_shadowing
        {
            constexpr const auto mask = 0x0000000000004000UL;
            constexpr const auto from = 14;
            constexpr const auto name = "vmcs_shadowing";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace rdseed_exiting
        {
            constexpr const auto mask = 0x0000000000010000UL;
            constexpr const auto from = 16;
            constexpr const auto name = "rdseed_exiting";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace enable_pml
        {
            constexpr const auto mask = 0x0000000000020000UL;
            constexpr const auto from = 17;
            constexpr const auto name = "enable_pml";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace ept_violation_ve
        {
            constexpr const auto mask = 0x0000000000040000UL;
            constexpr const auto from = 18;
            constexpr const auto name = "ept_violation_ve";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace enable_xsaves_xrstors
        {
            constexpr const auto mask = 0x0000000000100000UL;
            constexpr const auto from = 20;
            constexpr const auto name = "enable_xsaves_xrstors";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
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
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace page_walk_length_of_4
        {
            constexpr const auto mask = 0x0000000000000040UL;
            constexpr const auto from = 6;
            constexpr const auto name = "page_walk_length_of_4";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace memory_type_uncacheable_supported
        {
            constexpr const auto mask = 0x0000000000000100UL;
            constexpr const auto from = 8;
            constexpr const auto name = "memory_type_uncacheable_supported";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace memory_type_write_back_supported
        {
            constexpr const auto mask = 0x0000000000004000UL;
            constexpr const auto from = 14;
            constexpr const auto name = "memory_type_write_back_supported";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace pde_2mb_support
        {
            constexpr const auto mask = 0x0000000000010000UL;
            constexpr const auto from = 16;
            constexpr const auto name = "pde_2mb_support";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace pdpte_1mb_support
        {
            constexpr const auto mask = 0x0000000000020000UL;
            constexpr const auto from = 17;
            constexpr const auto name = "pdpte_1mb_support";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace invept_support
        {
            constexpr const auto mask = 0x0000000000100000UL;
            constexpr const auto from = 20;
            constexpr const auto name = "invept_support";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace accessed_dirty_support
        {
            constexpr const auto mask = 0x0000000000200000UL;
            constexpr const auto from = 21;
            constexpr const auto name = "accessed_dirty_support";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace invept_single_context_support
        {
            constexpr const auto mask = 0x0000000002000000UL;
            constexpr const auto from = 25;
            constexpr const auto name = "invept_single_context_support";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace invept_all_context_support
        {
            constexpr const auto mask = 0x0000000004000000UL;
            constexpr const auto from = 26;
            constexpr const auto name = "invept_all_context_support";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace invvpid_support
        {
            constexpr const auto mask = 0x0000000100000000UL;
            constexpr const auto from = 32;
            constexpr const auto name = "invvpid_support";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace invvpid_individual_address_support
        {
            constexpr const auto mask = 0x0000010000000000UL;
            constexpr const auto from = 40;
            constexpr const auto name = "invvpid_individual_address_support";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace invvpid_single_context_support
        {
            constexpr const auto mask = 0x0000020000000000UL;
            constexpr const auto from = 41;
            constexpr const auto name = "invvpid_single_context_support";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace invvpid_all_context_support
        {
            constexpr const auto mask = 0x0000040000000000UL;
            constexpr const auto from = 42;
            constexpr const auto name = "invvpid_all_context_support";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace invvpid_single_context_retaining_globals_support
        {
            constexpr const auto mask = 0x0000080000000000UL;
            constexpr const auto from = 43;
            constexpr const auto name = "invvpid_single_context_retaining_globals_support";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }
    }

    namespace ia32_vmx_true_pinbased_ctls
    {
        constexpr const auto addr = 0x0000048DU;
        constexpr const auto name = "ia32_vmx_true_pinbased_ctls";

        inline auto get() noexcept
        { return __read_msr(addr); }

        namespace external_interrupt_exiting
        {
            constexpr const auto mask = 0x0000000000000001UL;
            constexpr const auto from = 0;
            constexpr const auto name = "external_interrupt_exiting";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace nmi_exiting
        {
            constexpr const auto mask = 0x0000000000000008UL;
            constexpr const auto from = 3;
            constexpr const auto name = "nmi_exiting";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace virtual_nmis
        {
            constexpr const auto mask = 0x0000000000000020UL;
            constexpr const auto from = 5;
            constexpr const auto name = "virtual_nmis";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace activate_vmx_preemption_timer
        {
            constexpr const auto mask = 0x0000000000000040UL;
            constexpr const auto from = 6;
            constexpr const auto name = "activate_vmx_preemption_timer";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace process_posted_interrupts
        {
            constexpr const auto mask = 0x0000000000000080UL;
            constexpr const auto from = 7;
            constexpr const auto name = "process_posted_interrupts";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }
    }

    namespace ia32_vmx_true_procbased_ctls
    {
        constexpr const auto addr = 0x0000048EU;
        constexpr const auto name = "ia32_vmx_true_procbased_ctls";

        inline auto get() noexcept
        { return __read_msr(addr); }

        namespace interrupt_window_exiting
        {
            constexpr const auto mask = 0x0000000000000004UL;
            constexpr const auto from = 2;
            constexpr const auto name = "interrupt_window_exiting";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace use_tsc_offsetting
        {
            constexpr const auto mask = 0x0000000000000008UL;
            constexpr const auto from = 2;
            constexpr const auto name = "use_tsc_offsetting";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace hlt_exiting
        {
            constexpr const auto mask = 0x0000000000000080UL;
            constexpr const auto from = 7;
            constexpr const auto name = "hlt_exiting";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace invlpg_exiting
        {
            constexpr const auto mask = 0x0000000000000200UL;
            constexpr const auto from = 9;
            constexpr const auto name = "invlpg_exiting";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace mwait_exiting
        {
            constexpr const auto mask = 0x0000000000000400UL;
            constexpr const auto from = 10;
            constexpr const auto name = "mwait_exiting";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace rdpmc_exiting
        {
            constexpr const auto mask = 0x0000000000000800UL;
            constexpr const auto from = 11;
            constexpr const auto name = "rdpmc_exiting";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace rdtsc_exiting
        {
            constexpr const auto mask = 0x0000000000001000UL;
            constexpr const auto from = 12;
            constexpr const auto name = "rdtsc_exiting";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace cr3_load_exiting
        {
            constexpr const auto mask = 0x0000000000008000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "cr3_load_exiting";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace cr3_store_exiting
        {
            constexpr const auto mask = 0x0000000000010000UL;
            constexpr const auto from = 16;
            constexpr const auto name = "cr3_store_exiting";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace cr8_load_exiting
        {
            constexpr const auto mask = 0x0000000000080000UL;
            constexpr const auto from = 19;
            constexpr const auto name = "cr8_load_exiting";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace cr8_store_exiting
        {
            constexpr const auto mask = 0x0000000000100000UL;
            constexpr const auto from = 20;
            constexpr const auto name = "cr8_store_exiting";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace use_tpr_shadow
        {
            constexpr const auto mask = 0x0000000000200000UL;
            constexpr const auto from = 21;
            constexpr const auto name = "use_tpr_shadow";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace nmi_window_exiting
        {
            constexpr const auto mask = 0x0000000000400000UL;
            constexpr const auto from = 22;
            constexpr const auto name = "nmi_window_exiting";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace mov_dr_exiting
        {
            constexpr const auto mask = 0x0000000000800000UL;
            constexpr const auto from = 23;
            constexpr const auto name = "mov_dr_exiting";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace unconditional_io_exiting
        {
            constexpr const auto mask = 0x0000000001000000UL;
            constexpr const auto from = 24;
            constexpr const auto name = "unconditional_io_exiting";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace use_io_bitmaps
        {
            constexpr const auto mask = 0x0000000002000000UL;
            constexpr const auto from = 25;
            constexpr const auto name = "use_io_bitmaps";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace monitor_trap_flag
        {
            constexpr const auto mask = 0x0000000008000000UL;
            constexpr const auto from = 27;
            constexpr const auto name = "monitor_trap_flag";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace use_msr_bitmaps
        {
            constexpr const auto mask = 0x0000000010000000UL;
            constexpr const auto from = 28;
            constexpr const auto name = "use_msr_bitmaps";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace monitor_exiting
        {
            constexpr const auto mask = 0x0000000020000000UL;
            constexpr const auto from = 29;
            constexpr const auto name = "monitor_exiting";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace pause_exiting
        {
            constexpr const auto mask = 0x0000000040000000UL;
            constexpr const auto from = 30;
            constexpr const auto name = "pause_exiting";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace activate_secondary_controls
        {
            constexpr const auto mask = 0x0000000080000000UL;
            constexpr const auto from = 31;
            constexpr const auto name = "activate_secondary_controls";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }
    }

    namespace ia32_vmx_true_exit_ctls
    {
        constexpr const auto addr = 0x0000048FU;
        constexpr const auto name = "ia32_vmx_true_exit_ctls";

        inline auto get() noexcept
        { return __read_msr(addr); }

        namespace save_debug_controls
        {
            constexpr const auto mask = 0x0000000000000004UL;
            constexpr const auto from = 2;
            constexpr const auto name = "save_debug_controls";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace host_address_space_size
        {
            constexpr const auto mask = 0x0000000000000200UL;
            constexpr const auto from = 9;
            constexpr const auto name = "host_address_space_size";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace load_ia32_perf_global_ctrl
        {
            constexpr const auto mask = 0x0000000000001000UL;
            constexpr const auto from = 12;
            constexpr const auto name = "load_ia32_perf_global_ctrl";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace acknowledge_interrupt_on_exit
        {
            constexpr const auto mask = 0x0000000000008000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "acknowledge_interrupt_on_exit";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace save_ia32_pat
        {
            constexpr const auto mask = 0x0000000000040000UL;
            constexpr const auto from = 18;
            constexpr const auto name = "save_ia32_pat";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace load_ia32_pat
        {
            constexpr const auto mask = 0x0000000000080000UL;
            constexpr const auto from = 19;
            constexpr const auto name = "load_ia32_pat";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace save_ia32_efer
        {
            constexpr const auto mask = 0x0000000000100000UL;
            constexpr const auto from = 20;
            constexpr const auto name = "save_ia32_efer";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace load_ia32_efer
        {
            constexpr const auto mask = 0x0000000000200000UL;
            constexpr const auto from = 21;
            constexpr const auto name = "load_ia32_efer";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace save_vmx_preemption_timer_value
        {
            constexpr const auto mask = 0x0000000000400000UL;
            constexpr const auto from = 22;
            constexpr const auto name = "save_vmx_preemption_timer_value";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }
    }

    namespace ia32_vmx_true_entry_ctls
    {
        constexpr const auto addr = 0x00000490U;
        constexpr const auto name = "ia32_vmx_true_entry_ctls";

        inline auto get() noexcept
        { return __read_msr(addr); }

        namespace load_debug_controls
        {
            constexpr const auto mask = 0x0000000000000004UL;
            constexpr const auto from = 2;
            constexpr const auto name = "load_debug_controls";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace ia_32e_mode_guest
        {
            constexpr const auto mask = 0x0000000000000200UL;
            constexpr const auto from = 9;
            constexpr const auto name = "ia_32e_mode_guest";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace entry_to_smm
        {
            constexpr const auto mask = 0x0000000000000400UL;
            constexpr const auto from = 10;
            constexpr const auto name = "entry_to_smm";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace deactivate_dual_monitor_treatment
        {
            constexpr const auto mask = 0x0000000000000800UL;
            constexpr const auto from = 11;
            constexpr const auto name = "deactivate_dual_monitor_treatment";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace load_ia32_perf_global_ctrl
        {
            constexpr const auto mask = 0x0000000000002000UL;
            constexpr const auto from = 13;
            constexpr const auto name = "load_ia32_perf_global_ctrl";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace load_ia32_pat
        {
            constexpr const auto mask = 0x0000000000004000UL;
            constexpr const auto from = 14;
            constexpr const auto name = "load_ia32_pat";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
        }

        namespace load_ia32_efer
        {
            constexpr const auto mask = 0x0000000000008000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "load_ia32_efer";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }
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

        template<class T> void set(T val) noexcept
        { __write_msr(addr, val); }

        namespace sce
        {
            constexpr const auto mask = 0x0000000000000001UL;
            constexpr const auto from = 0;
            constexpr const auto name = "sce";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace lme
        {
            constexpr const auto mask = 0x0000000000000100UL;
            constexpr const auto from = 8;
            constexpr const auto name = "lme";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace lma
        {
            constexpr const auto mask = 0x0000000000000400UL;
            constexpr const auto from = 10;
            constexpr const auto name = "lma";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace nxe
        {
            constexpr const auto mask = 0x0000000000000800UL;
            constexpr const auto from = 11;
            constexpr const auto name = "lma";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }

        namespace reserved
        {
            constexpr const auto mask = 0xFFFFFFFFFFFFF2FEUL;
            constexpr const auto from = 0;
            constexpr const auto name = "reserved";

            inline auto get() noexcept
            { return (__read_msr(addr) & mask) >> from; }

            template<class T> void set(T val) noexcept
            { __write_msr(addr, (__read_msr(addr) & ~mask) | ((val << from) & mask)); }
        }
    }

    namespace ia32_fs_base
    {
        constexpr const auto addr = 0xC0000100U;
        constexpr const auto name = "ia32_fs_base";

        inline auto get() noexcept
        { return __read_msr(addr); }

        template<class T> void set(T val) noexcept
        { __write_msr(addr, val); }
    }

    namespace ia32_gs_base
    {
        constexpr const auto addr = 0xC0000101U;
        constexpr const auto name = "ia32_gs_base";

        inline auto get() noexcept
        { return __read_msr(addr); }

        template<class T> void set(T val) noexcept
        { __write_msr(addr, val); }
    }
}
}

// *INDENT-ON*

#endif
