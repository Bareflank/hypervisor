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

#ifndef MSRS_INTEL_X64_h
#define MSRS_INTEL_X64_h

#include <gsl/gsl>

extern "C" uint64_t __read_msr(uint32_t msr) noexcept;

// *INDENT-OFF*

namespace intel_x64
{
namespace msrs
{
    template<class I, class T> constexpr auto
    read_msr(I in, T msr)
    { return in->read_msr(msr); }

    namespace ia32_feature_control
    {
        constexpr const auto addr = 0x0000003AU;
        constexpr const auto name = "ia32_feature_control";

        inline auto get() noexcept
        { return __read_msr(addr); }

        namespace lock_bit
        {
            constexpr const auto mask = 0x0000000000000001UL;
            constexpr const auto from = 0;
            constexpr const auto name = "lock_bit";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace enable_vmx_inside_smx
        {
            constexpr const auto mask = 0x0000000000000002UL;
            constexpr const auto from = 1;
            constexpr const auto name = "enable_vmx_inside_smx";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace enable_vmx_outside_smx
        {
            constexpr const auto mask = 0x0000000000000004UL;
            constexpr const auto from = 2;
            constexpr const auto name = "enable_vmx_outside_smx";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
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
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace vmxon_vmcs_region_size
        {
            constexpr const auto mask = 0x00001FFF00000000UL;
            constexpr const auto from = 32;
            constexpr const auto name = "vmxon_vmcs_region_size";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace physical_address_width
        {
            constexpr const auto mask = 0x0001000000000000UL;
            constexpr const auto from = 48;
            constexpr const auto name = "physical_address_width";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace dual_monitor_mode_support
        {
            constexpr const auto mask = 0x0002000000000000UL;
            constexpr const auto from = 49;
            constexpr const auto name = "dual_monitor_mode_support";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace memory_type
        {
            constexpr const auto mask = 0x003C000000000000UL;
            constexpr const auto from = 50;
            constexpr const auto name = "memory_type";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace ins_outs_exit_information
        {
            constexpr const auto mask = 0x0040000000000000UL;
            constexpr const auto from = 54;
            constexpr const auto name = "ins_outs_exit_information";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace true_based_controls
        {
            constexpr const auto mask = 0x0080000000000000UL;
            constexpr const auto from = 55;
            constexpr const auto name = "true_based_controls";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
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
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace store_efer_lma_on_vm_exit
        {
            constexpr const auto mask = 0x0000000000000020UL;
            constexpr const auto from = 5;
            constexpr const auto name = "store_efer_lma_on_vm_exit";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace activity_state_hlt_support
        {
            constexpr const auto mask = 0x0000000000000040UL;
            constexpr const auto from = 6;
            constexpr const auto name = "activity_state_hlt_support";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace activity_state_shutdown_support
        {
            constexpr const auto mask = 0x0000000000000080UL;
            constexpr const auto from = 7;
            constexpr const auto name = "activity_state_shutdown_support";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace activity_state_wait_for_sipi_support
        {
            constexpr const auto mask = 0x0000000000000100UL;
            constexpr const auto from = 8;
            constexpr const auto name = "activity_state_wait_for_sipi_support";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace processor_trace_support
        {
            constexpr const auto mask = 0x0000000000004000UL;
            constexpr const auto from = 14;
            constexpr const auto name = "processor_trace_support";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace rdmsr_in_smm_support
        {
            constexpr const auto mask = 0x0000000000008000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "rdmsr_in_smm_support";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace cr3_targets
        {
            constexpr const auto mask = 0x0000000001FF0000UL;
            constexpr const auto from = 16;
            constexpr const auto name = "cr3_targets";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace max_num_msr_load_store_on_exit
        {
            constexpr const auto mask = 0x000000000E000000UL;
            constexpr const auto from = 25;
            constexpr const auto name = "max_num_msr_load_store_on_exit";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace vmxoff_blocked_smi_support
        {
            constexpr const auto mask = 0x0000000010000000UL;
            constexpr const auto from = 28;
            constexpr const auto name = "vmxoff_blocked_smi_support";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace vmwrite_all_fields_support
        {
            constexpr const auto mask = 0x0000000020000000UL;
            constexpr const auto from = 29;
            constexpr const auto name = "vmwrite_all_fields_support";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace injection_with_instruction_length_of_zero
        {
            constexpr const auto mask = 0x0000000040000000UL;
            constexpr const auto from = 30;
            constexpr const auto name = "injection_with_instruction_length_of_zero";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
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
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace page_walk_length_of_4
        {
            constexpr const auto mask = 0x0000000000000040UL;
            constexpr const auto from = 6;
            constexpr const auto name = "page_walk_length_of_4";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace memory_type_uncacheable_supported
        {
            constexpr const auto mask = 0x0000000000000100UL;
            constexpr const auto from = 8;
            constexpr const auto name = "memory_type_uncacheable_supported";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace memory_type_write_back_supported
        {
            constexpr const auto mask = 0x0000000000004000UL;
            constexpr const auto from = 14;
            constexpr const auto name = "memory_type_write_back_supported";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace pde_2mb_support
        {
            constexpr const auto mask = 0x0000000000010000UL;
            constexpr const auto from = 16;
            constexpr const auto name = "pde_2mb_support";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace pdpte_1mb_support
        {
            constexpr const auto mask = 0x0000000000020000UL;
            constexpr const auto from = 17;
            constexpr const auto name = "pdpte_1mb_support";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace invept_support
        {
            constexpr const auto mask = 0x0000000000100000UL;
            constexpr const auto from = 20;
            constexpr const auto name = "invept_support";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace accessed_dirty_support
        {
            constexpr const auto mask = 0x0000000000200000UL;
            constexpr const auto from = 21;
            constexpr const auto name = "accessed_dirty_support";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace invept_single_context_support
        {
            constexpr const auto mask = 0x0000000002000000UL;
            constexpr const auto from = 25;
            constexpr const auto name = "invept_single_context_support";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace invept_all_context_support
        {
            constexpr const auto mask = 0x0000000004000000UL;
            constexpr const auto from = 26;
            constexpr const auto name = "invept_all_context_support";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace invvpid_support
        {
            constexpr const auto mask = 0x0000000100000000UL;
            constexpr const auto from = 32;
            constexpr const auto name = "invvpid_support";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace invvpid_individual_address_support
        {
            constexpr const auto mask = 0x0000010000000000UL;
            constexpr const auto from = 40;
            constexpr const auto name = "invvpid_individual_address_support";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace invvpid_single_context_support
        {
            constexpr const auto mask = 0x0000020000000000UL;
            constexpr const auto from = 41;
            constexpr const auto name = "invvpid_single_context_support";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace invvpid_all_context_support
        {
            constexpr const auto mask = 0x0000040000000000UL;
            constexpr const auto from = 42;
            constexpr const auto name = "invvpid_all_context_support";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }

        namespace invvpid_single_context_retaining_globals_support
        {
            constexpr const auto mask = 0x0000080000000000UL;
            constexpr const auto from = 43;
            constexpr const auto name = "invvpid_single_context_retaining_globals_support";

            inline auto get() noexcept
            { return gsl::narrow_cast<uint32_t>((__read_msr(addr) & mask) >> from); }
        }
    }

    namespace ia32_vmx_true_pinbased_ctls
    {
        constexpr const auto addr = 0x0000048DU;
        constexpr const auto name = "ia32_vmx_true_pinbased_ctls";

        inline auto get() noexcept
        { return __read_msr(addr); }
    }

    namespace ia32_vmx_true_procbased_ctls
    {
        constexpr const auto addr = 0x0000048EU;
        constexpr const auto name = "ia32_vmx_true_procbased_ctls";

        inline auto get() noexcept
        { return __read_msr(addr); }
    }

    namespace ia32_vmx_true_exit_ctls
    {
        constexpr const auto addr = 0x0000048FU;
        constexpr const auto name = "ia32_vmx_true_exit_ctls";

        inline auto get() noexcept
        { return __read_msr(addr); }
    }

    namespace ia32_vmx_true_entry_ctls
    {
        constexpr const auto addr = 0x00000490U;
        constexpr const auto name = "ia32_vmx_true_entry_ctls";

        inline auto get() noexcept
        { return __read_msr(addr); }
    }

    namespace ia32_vmx_vmfunc
    {
        constexpr const auto addr = 0x00000491U;
        constexpr const auto name = "ia32_vmx_vmfunc";

        inline auto get() noexcept
        { return __read_msr(addr); }
    }
}
}

// *INDENT-ON*

#endif
