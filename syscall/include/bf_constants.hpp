/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#ifndef BF_CONSTANTS_HPP
#define BF_CONSTANTS_HPP

#include <bsl/convert.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_integral.hpp>

namespace syscall
{
    // -------------------------------------------------------------------------
    // Page Alignment
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Returns true if the provided address is 4k page aligned,
    ///     returns false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param addr the address to query
    ///   @return Returns true if the provided address is 4k page aligned,
    ///     returns false otherwise.
    ///
    [[nodiscard]] constexpr auto
    bf_is_page_aligned(bsl::safe_u64 const &addr) noexcept -> bool
    {
        bsl::expects(addr.is_valid_and_checked());

        constexpr auto mask{HYPERVISOR_PAGE_SIZE - bsl::safe_u64::magic_1()};
        return (addr & mask).is_zero();
    }

    /// <!-- description -->
    ///   @brief Returns the page aligned version of the addr
    ///
    /// <!-- inputs/outputs -->
    ///   @param addr the address to query
    ///   @return Returns the page aligned version of the addr
    ///
    [[nodiscard]] static constexpr auto
    bf_page_aligned(bsl::safe_umx const &addr) noexcept -> bsl::safe_umx
    {
        bsl::expects(addr.is_valid_and_checked());
        return (addr & ~(HYPERVISOR_PAGE_SIZE - bsl::safe_u64::magic_1()));
    }

    // -------------------------------------------------------------------------
    // Special IDs
    // -------------------------------------------------------------------------

    /// @brief Defines an invalid ID for an extension, VM, VP and VS
    constexpr auto BF_INVALID_ID{0xFFFF_u16};

    /// @brief Defines the bootstrap physical processor ID
    constexpr auto BF_BS_PPID{0x0_u16};

    /// @brief Defines the root virtual machine ID
    constexpr auto BF_ROOT_VMID{0x0_u16};

    // -------------------------------------------------------------------------
    // Syscall Status Codes
    // -------------------------------------------------------------------------

    /// @brief Indicates the syscall returned successfully
    constexpr auto BF_STATUS_SUCCESS{0x0000000000000000_u64};
    /// @brief Indicates an unknown error occurred
    constexpr auto BF_STATUS_FAILURE_UNKNOWN{0xDEAD000000010001_u64};
    /// @brief Indicates the syscall is unsupported
    constexpr auto BF_STATUS_FAILURE_INVALID_HANDLE{0xDEAD000000020001_u64};
    /// @brief Indicates the provided handle is invalid
    constexpr auto BF_STATUS_FAILURE_UNSUPPORTED{0xDEAD000000040001_u64};
    /// @brief Indicates the policy engine denied the syscall
    constexpr auto BF_STATUS_INVALID_PERM_DENIED{0xDEAD000000010002_u64};
    /// @brief Indicates input reg0 is invalid
    constexpr auto BF_STATUS_INVALID_INPUT_REG0{0xDEAD000000010003_u64};
    /// @brief Indicates input reg1 is invalid
    constexpr auto BF_STATUS_INVALID_INPUT_REG1{0xDEAD000000020003_u64};
    /// @brief Indicates input reg2 is invalid
    constexpr auto BF_STATUS_INVALID_INPUT_REG2{0xDEAD000000040003_u64};
    /// @brief Indicates input reg3 is invalid
    constexpr auto BF_STATUS_INVALID_INPUT_REG3{0xDEAD000000080003_u64};
    /// @brief Indicates input reg4 is invalid
    constexpr auto BF_STATUS_INVALID_INPUT_REG4{0xDEAD000000100003_u64};
    /// @brief Indicates input reg5 is invalid
    constexpr auto BF_STATUS_INVALID_INPUT_REG5{0xDEAD000000200003_u64};
    /// @brief Indicates output reg0 is invalid
    constexpr auto BF_STATUS_INVALID_OUTPUT_REG0{0xDEAD000000400003_u64};
    /// @brief Indicates output reg1 is invalid
    constexpr auto BF_STATUS_INVALID_OUTPUT_REG1{0xDEAD000000800003_u64};
    /// @brief Indicates output reg2 is invalid
    constexpr auto BF_STATUS_INVALID_OUTPUT_REG2{0xDEAD000001000003_u64};
    /// @brief Indicates output reg3 is invalid
    constexpr auto BF_STATUS_INVALID_OUTPUT_REG3{0xDEAD000002000003_u64};
    /// @brief Indicates output reg4 is invalid
    constexpr auto BF_STATUS_INVALID_OUTPUT_REG4{0xDEAD000004000003_u64};
    /// @brief Indicates output reg5 is invalid
    constexpr auto BF_STATUS_INVALID_OUTPUT_REG5{0xDEAD000008000003_u64};

    // -------------------------------------------------------------------------
    // Syscall Inputs
    // -------------------------------------------------------------------------

    /// @brief Defines the BF_SYSCALL_SIG field for RAX
    constexpr auto BF_SYSCALL_SIG_VAL{0x6642000000000000_u64};
    /// @brief Defines a mask for BF_SYSCALL_SIG
    constexpr auto BF_SYSCALL_SIG_MASK{0xFFFF000000000000_u64};
    /// @brief Defines a mask for BF_SYSCALL_FLAGS
    constexpr auto BF_SYSCALL_FLAGS_MASK{0x0000FFFF00000000_u64};
    /// @brief Defines a mask for BF_SYSCALL_OP
    constexpr auto BF_SYSCALL_OPCODE_MASK{0xFFFF0000FFFF0000_u64};
    /// @brief Defines a mask for BF_SYSCALL_OP (with no signature added)
    constexpr auto BF_SYSCALL_OPCODE_NOSIG_MASK{0x00000000FFFF0000_u64};
    /// @brief Defines a mask for BF_SYSCALL_IDX
    constexpr auto BF_SYSCALL_INDEX_MASK{0x000000000000FFFF_u64};

    /// <!-- description -->
    ///   @brief n/a
    ///
    /// <!-- inputs/outputs -->
    ///   @param rax n/a
    ///   @return n/a
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    bf_syscall_sig(bsl::uint64 const &rax) noexcept -> bsl::safe_u64
    {
        return rax & BF_SYSCALL_SIG_MASK;
    }

    /// <!-- description -->
    ///   @brief n/a
    ///
    /// <!-- inputs/outputs -->
    ///   @param rax n/a
    ///   @return n/a
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    bf_syscall_flags(bsl::uint64 const &rax) noexcept -> bsl::safe_u64
    {
        return rax & BF_SYSCALL_FLAGS_MASK;
    }

    /// <!-- description -->
    ///   @brief n/a
    ///
    /// <!-- inputs/outputs -->
    ///   @param rax n/a
    ///   @return n/a
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    bf_syscall_opcode(bsl::uint64 const &rax) noexcept -> bsl::safe_u64
    {
        return rax & BF_SYSCALL_OPCODE_MASK;
    }

    /// <!-- description -->
    ///   @brief n/a
    ///
    /// <!-- inputs/outputs -->
    ///   @param rax n/a
    ///   @return n/a
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    bf_syscall_opcode_nosig(bsl::uint64 const &rax) noexcept -> bsl::safe_u64
    {
        return rax & BF_SYSCALL_OPCODE_NOSIG_MASK;
    }

    /// <!-- description -->
    ///   @brief n/a
    ///
    /// <!-- inputs/outputs -->
    ///   @param rax n/a
    ///   @return n/a
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    bf_syscall_index(bsl::uint64 const &rax) noexcept -> bsl::safe_u64
    {
        return rax & BF_SYSCALL_INDEX_MASK;
    }

    // -------------------------------------------------------------------------
    // Specification IDs
    // -------------------------------------------------------------------------

    /// @brief Defines the ID for version #1 of this spec
    constexpr auto BF_SPEC_ID1_VAL{0x31236642_u32};

    /// @brief Defines the mask for checking support for version #1 of this spec
    constexpr auto BF_SPEC_ID1_MASK{0x2_u32};

    /// @brief Defines all versions supported
    constexpr auto BF_ALL_SPECS_SUPPORTED_VAL{0x2_u32};

    /// @brief Defines an invalid version
    constexpr auto BF_INVALID_VERSION{0x80000000_u32};

    /// <!-- description -->
    ///   @brief n/a
    ///
    /// <!-- inputs/outputs -->
    ///   @param version n/a
    ///   @return n/a
    ///
    [[nodiscard]] constexpr auto
    bf_is_spec1_supported(bsl::safe_u32 const &version) noexcept -> bool
    {
        bsl::expects(version.is_valid_and_checked());
        return (version & BF_SPEC_ID1_MASK).is_pos();
    }

    // -------------------------------------------------------------------------
    // Syscall Opcodes - Control Support
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall opcode for bf_control_op
    constexpr auto BF_CONTROL_OP_VAL{0x6642000000000000_u64};
    /// @brief Defines the syscall opcode for bf_control_op (nosig)
    constexpr auto BF_CONTROL_OP_NOSIG_VAL{0x0000000000000000_u64};

    // -------------------------------------------------------------------------
    // Syscall Opcodes - Handle Support
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall opcode for bf_handle_op
    constexpr auto BF_HANDLE_OP_VAL{0x6642000000010000_u64};
    /// @brief Defines the syscall opcode for bf_handle_op (nosig)
    constexpr auto BF_HANDLE_OP_NOSIG_VAL{0x0000000000010000_u64};

    // -------------------------------------------------------------------------
    // Syscall Opcodes - Debug Support
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall opcode for bf_debug_op
    constexpr auto BF_DEBUG_OP_VAL{0x6642000000020000_u64};
    /// @brief Defines the syscall opcode for bf_debug_op (nosig)
    constexpr auto BF_DEBUG_OP_NOSIG_VAL{0x00000000000020000_u64};

    // -------------------------------------------------------------------------
    // Syscall Opcodes - Callback Support
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall opcode for bf_callback_op
    constexpr auto BF_CALLBACK_OP_VAL{0x6642000000030000_u64};
    /// @brief Defines the syscall opcode for bf_callback_op (nosig)
    constexpr auto BF_CALLBACK_OP_NOSIG_VAL{0x0000000000030000_u64};

    // -------------------------------------------------------------------------
    // Syscall Opcodes - VM Support
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall opcode for bf_vm_op
    constexpr auto BF_VM_OP_VAL{0x6642000000040000_u64};
    /// @brief Defines the syscall opcode for bf_vm_op (nosig)
    constexpr auto BF_VM_OP_NOSIG_VAL{0x0000000000040000_u64};

    // -------------------------------------------------------------------------
    // Syscall Opcodes - VP Support
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall opcode for bf_vp_op
    constexpr auto BF_VP_OP_VAL{0x6642000000050000_u64};
    /// @brief Defines the syscall opcode for bf_vp_op (nosig)
    constexpr auto BF_VP_OP_NOSIG_VAL{0x0000000000050000_u64};

    // -------------------------------------------------------------------------
    // Syscall Opcodes - VS Support
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall opcode for bf_vs_op
    constexpr auto BF_VS_OP_VAL{0x6642000000060000_u64};
    /// @brief Defines the syscall opcode for bf_vs_op (nosig)
    constexpr auto BF_VS_OP_NOSIG_VAL{0x0000000000060000_u64};

    // -------------------------------------------------------------------------
    // Syscall Opcodes - Intrinsic Support
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall opcode for bf_intrinsic_op
    constexpr auto BF_INTRINSIC_OP_VAL{0x6642000000070000_u64};
    /// @brief Defines the syscall opcode for bf_intrinsic_op (nosig)
    constexpr auto BF_INTRINSIC_OP_NOSIG_VAL{0x0000000000070000_u64};

    // -------------------------------------------------------------------------
    // Syscall Opcodes - Mem Support
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall opcode for bf_mem_op
    constexpr auto BF_MEM_OP_VAL{0x6642000000080000_u64};
    /// @brief Defines the syscall opcode for bf_mem_op (nosig)
    constexpr auto BF_MEM_OP_NOSIG_VAL{0x0000000000080000_u64};

    // -------------------------------------------------------------------------
    // TLS Offsets
    // -------------------------------------------------------------------------

    /// @brief stores the offset for rax
    constexpr auto TLS_OFFSET_RAX{0x800_u64};
    /// @brief stores the offset for rbx
    constexpr auto TLS_OFFSET_RBX{0x808_u64};
    /// @brief stores the offset for rcx
    constexpr auto TLS_OFFSET_RCX{0x810_u64};
    /// @brief stores the offset for rdx
    constexpr auto TLS_OFFSET_RDX{0x818_u64};
    /// @brief stores the offset for rbp
    constexpr auto TLS_OFFSET_RBP{0x820_u64};
    /// @brief stores the offset for rsi
    constexpr auto TLS_OFFSET_RSI{0x828_u64};
    /// @brief stores the offset for rdi
    constexpr auto TLS_OFFSET_RDI{0x830_u64};
    /// @brief stores the offset for r8
    constexpr auto TLS_OFFSET_R8{0x838_u64};
    /// @brief stores the offset for r9
    constexpr auto TLS_OFFSET_R9{0x840_u64};
    /// @brief stores the offset for r10
    constexpr auto TLS_OFFSET_R10{0x848_u64};
    /// @brief stores the offset for r11
    constexpr auto TLS_OFFSET_R11{0x850_u64};
    /// @brief stores the offset for r12
    constexpr auto TLS_OFFSET_R12{0x858_u64};
    /// @brief stores the offset for r13
    constexpr auto TLS_OFFSET_R13{0x860_u64};
    /// @brief stores the offset for r14
    constexpr auto TLS_OFFSET_R14{0x868_u64};
    /// @brief stores the offset for r15
    constexpr auto TLS_OFFSET_R15{0x870_u64};
    /// @brief stores the offset of the active extid
    constexpr auto TLS_OFFSET_ACTIVE_EXTID{0xFF0_u64};
    /// @brief stores the offset of the active vmid
    constexpr auto TLS_OFFSET_ACTIVE_VMID{0xFF2_u64};
    /// @brief stores the offset of the active vpid
    constexpr auto TLS_OFFSET_ACTIVE_VPID{0xFF4_u64};
    /// @brief stores the offset of the active vsid
    constexpr auto TLS_OFFSET_ACTIVE_VSID{0xFF6_u64};
    /// @brief stores the offset of the active ppid
    constexpr auto TLS_OFFSET_ACTIVE_PPID{0xFF8_u64};
    /// @brief stores the number of PPs that are online
    constexpr auto TLS_OFFSET_ONLINE_PPS{0xFFA_u64};

    // -------------------------------------------------------------------------
    // Hypercall Related Constants
    // -------------------------------------------------------------------------

    /// @brief Defines an invalid handle
    constexpr auto BF_INVALID_HANDLE{0xFFFFFFFFFFFFFFFF_u64};

    // -------------------------------------------------------------------------
    // Syscall Indexes
    // -------------------------------------------------------------------------

    /// @brief Defines the index for bf_control_op_exit
    constexpr auto BF_CONTROL_OP_EXIT_IDX_VAL{0x0000000000000000_u64};
    /// @brief Defines the index for bf_control_op_wait
    constexpr auto BF_CONTROL_OP_WAIT_IDX_VAL{0x0000000000000001_u64};
    /// @brief Defines the index for bf_control_op_again
    constexpr auto BF_CONTROL_OP_AGAIN_IDX_VAL{0x0000000000000002_u64};

    /// @brief Defines the index for bf_handle_op_open_handle
    constexpr auto BF_HANDLE_OP_OPEN_HANDLE_IDX_VAL{0x0000000000000000_u64};
    /// @brief Defines the index for bf_handle_op_close_handle
    constexpr auto BF_HANDLE_OP_CLOSE_HANDLE_IDX_VAL{0x0000000000000001_u64};

    /// @brief Defines the index for bf_debug_op_out
    constexpr auto BF_DEBUG_OP_OUT_IDX_VAL{0x0000000000000000_u64};
    /// @brief Defines the index for bf_debug_op_dump_vm
    constexpr auto BF_DEBUG_OP_DUMP_VM_IDX_VAL{0x0000000000000001_u64};
    /// @brief Defines the index for bf_debug_op_dump_vp
    constexpr auto BF_DEBUG_OP_DUMP_VP_IDX_VAL{0x0000000000000002_u64};
    /// @brief Defines the index for bf_debug_op_dump_vs
    constexpr auto BF_DEBUG_OP_DUMP_VS_IDX_VAL{0x0000000000000003_u64};
    /// @brief Defines the index for bf_debug_op_dump_vmexit_log
    constexpr auto BF_DEBUG_OP_DUMP_VMEXIT_LOG_IDX_VAL{0x0000000000000004_u64};
    /// @brief Defines the index for bf_debug_op_write_c
    constexpr auto BF_DEBUG_OP_WRITE_C_IDX_VAL{0x0000000000000005_u64};
    /// @brief Defines the index for bf_debug_op_write_str
    constexpr auto BF_DEBUG_OP_WRITE_STR_IDX_VAL{0x0000000000000006_u64};
    /// @brief Defines the index for bf_debug_op_dump_ext
    constexpr auto BF_DEBUG_OP_DUMP_EXT_IDX_VAL{0x0000000000000007_u64};
    /// @brief Defines the index for bf_debug_op_dump_page_pool
    constexpr auto BF_DEBUG_OP_DUMP_PAGE_POOL_IDX_VAL{0x0000000000000008_u64};
    /// @brief Defines the index for bf_debug_op_dump_huge_pool
    constexpr auto BF_DEBUG_OP_DUMP_HUGE_POOL_IDX_VAL{0x0000000000000009_u64};

    /// @brief Defines the index for bf_callback_op_register_bootstrap
    constexpr auto BF_CALLBACK_OP_REGISTER_BOOTSTRAP_IDX_VAL{0x0000000000000000_u64};
    /// @brief Defines the index for bf_callback_op_register_vmexit
    constexpr auto BF_CALLBACK_OP_REGISTER_VMEXIT_IDX_VAL{0x0000000000000001_u64};
    /// @brief Defines the index for bf_callback_op_register_fail
    constexpr auto BF_CALLBACK_OP_REGISTER_FAIL_IDX_VAL{0x0000000000000002_u64};

    /// @brief Defines the index for bf_vm_op_create_vm
    constexpr auto BF_VM_OP_CREATE_VM_IDX_VAL{0x0000000000000000_u64};
    /// @brief Defines the index for bf_vm_op_destroy_vm
    constexpr auto BF_VM_OP_DESTROY_VM_IDX_VAL{0x0000000000000001_u64};
    /// @brief Defines the index for bf_vm_op_map_direct
    constexpr auto BF_VM_OP_MAP_DIRECT_IDX_VAL{0x0000000000000002_u64};
    /// @brief Defines the index for bf_vm_op_unmap_direct
    constexpr auto BF_VM_OP_UNMAP_DIRECT_IDX_VAL{0x0000000000000003_u64};
    /// @brief Defines the index for bf_vm_op_unmap_direct_broadcast
    constexpr auto BF_VM_OP_UNMAP_DIRECT_BROADCAST_IDX_VAL{0x0000000000000004_u64};
    /// @brief Defines the index for bf_vm_op_tlb_flush
    constexpr auto BF_VM_OP_TLB_FLUSH_IDX_VAL{0x0000000000000005_u64};

    /// @brief Defines the index for bf_vp_op_create_vp
    constexpr auto BF_VP_OP_CREATE_VP_IDX_VAL{0x0000000000000000_u64};
    /// @brief Defines the index for bf_vp_op_destroy_vp
    constexpr auto BF_VP_OP_DESTROY_VP_IDX_VAL{0x0000000000000001_u64};

    /// @brief Defines the index for bf_vs_op_create_vs
    constexpr auto BF_VS_OP_CREATE_VS_IDX_VAL{0x0000000000000000_u64};
    /// @brief Defines the index for bf_vs_op_destroy_vs
    constexpr auto BF_VS_OP_DESTROY_VS_IDX_VAL{0x0000000000000001_u64};
    /// @brief Defines the index for bf_vs_op_init_as_root
    constexpr auto BF_VS_OP_INIT_AS_ROOT_IDX_VAL{0x0000000000000002_u64};
    /// @brief Defines the index for bf_vs_op_read_reg
    constexpr auto BF_VS_OP_READ_IDX_VAL{0x0000000000000003_u64};
    /// @brief Defines the index for bf_vs_op_write_reg
    constexpr auto BF_VS_OP_WRITE_IDX_VAL{0x0000000000000004_u64};
    /// @brief Defines the index for bf_vs_op_run
    constexpr auto BF_VS_OP_RUN_IDX_VAL{0x0000000000000005_u64};
    /// @brief Defines the index for bf_vs_op_run_current
    constexpr auto BF_VS_OP_RUN_CURRENT_IDX_VAL{0x0000000000000006_u64};
    /// @brief Defines the index for bf_vs_op_advance_ip_and_run
    constexpr auto BF_VS_OP_ADVANCE_IP_AND_RUN_IDX_VAL{0x0000000000000007_u64};
    /// @brief Defines the index for bf_vs_op_advance_ip_and_run_current
    constexpr auto BF_VS_OP_ADVANCE_IP_AND_RUN_CURRENT_IDX_VAL{0x0000000000000008_u64};
    /// @brief Defines the index for bf_vs_op_promote
    constexpr auto BF_VS_OP_PROMOTE_IDX_VAL{0x0000000000000009_u64};
    /// @brief Defines the index for bf_vs_op_clear
    constexpr auto BF_VS_OP_CLEAR_IDX_VAL{0x000000000000000A_u64};
    /// @brief Defines the index for bf_vs_op_migrate
    constexpr auto BF_VS_OP_MIGRATE_IDX_VAL{0x000000000000000B_u64};
    /// @brief Defines the index for bf_vs_op_set_active
    constexpr auto BF_VS_OP_SET_ACTIVE_IDX_VAL{0x000000000000000C_u64};
    /// @brief Defines the index for bf_vs_op_advance_ip_and_set_active
    constexpr auto BF_VS_OP_ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL{0x000000000000000D_u64};
    /// @brief Defines the index for bf_vs_op_tlb_flush
    constexpr auto BF_VS_OP_TLB_FLUSH_IDX_VAL{0x000000000000000E_u64};

    /// @brief Defines the index for bf_intrinsic_op_rdmsr
    constexpr auto BF_INTRINSIC_OP_RDMSR_IDX_VAL{0x0000000000000000_u64};
    /// @brief Defines the index for bf_intrinsic_op_wrmsr
    constexpr auto BF_INTRINSIC_OP_WRMSR_IDX_VAL{0x0000000000000001_u64};

    /// @brief Defines the index for bf_mem_op_alloc_page
    constexpr auto BF_MEM_OP_ALLOC_PAGE_IDX_VAL{0x0000000000000000_u64};
    /// @brief Defines the index for bf_mem_op_alloc_huge
    constexpr auto BF_MEM_OP_ALLOC_HUGE_IDX_VAL{0x0000000000000002_u64};
}

#endif
