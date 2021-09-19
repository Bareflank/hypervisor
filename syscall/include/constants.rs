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
pub fn bf_is_page_aligned(addr: u64) -> bool {
    const MASK: u64 = cmake::HYPERVISOR_PAGE_SIZE - 1;
    return (addr & MASK) == 0;
}

#[cfg(test)]
mod test_bf_is_page_aligned {
    #[test]
    fn test_bf_is_page_aligned() {
        let addr: u64 = 0x1234567890ABCDEF;
        assert!(!super::bf_is_page_aligned(addr));
    }
}

/// <!-- description -->
///   @brief Returns the page aligned version of the addr
///
/// <!-- inputs/outputs -->
///   @param addr the address to query
///   @return Returns the page aligned version of the addr
///
pub fn bf_page_aligned(addr: u64) -> u64 {
    return addr & !(cmake::HYPERVISOR_PAGE_SIZE - 1);
}

#[cfg(test)]
mod test_bf_page_aligned {
    #[test]
    fn test_bf_page_aligned() {
        let addr: u64 = 0x1234567890ABCDEF;
        let expected: u64 = 0x1234567890ABC000;
        assert_eq!(super::bf_page_aligned(addr), expected);
    }
}

// -------------------------------------------------------------------------
// Special IDs
// -------------------------------------------------------------------------

/// @brief Defines an invalid ID for an extension, VM, VP and VS
pub const BF_INVALID_ID: u16 = 0xFFFF;

/// @brief Defines the bootstrap physical processor ID
pub const BF_BS_PPID: u16 = 0x0;

/// @brief Defines the root virtual machine ID
pub const BF_ROOT_VMID: u16 = 0x0;

// -------------------------------------------------------------------------
// Syscall Status Codes
// -------------------------------------------------------------------------

/// @brief Indicates the syscall returned successfully
pub const BF_STATUS_SUCCESS: u64 = 0x0000000000000000;
/// @brief Indicates an unknown error occurred
pub const BF_STATUS_FAILURE_UNKNOWN: u64 = 0xDEAD000000010001;
/// @brief Indicates the syscall is unsupported
pub const BF_STATUS_FAILURE_INVALID_HANDLE: u64 = 0xDEAD000000020001;
/// @brief Indicates the provided handle is invalid
pub const BF_STATUS_FAILURE_UNSUPPORTED: u64 = 0xDEAD000000040001;
/// @brief Indicates the policy engine denied the syscall
pub const BF_STATUS_INVALID_PERM_DENIED: u64 = 0xDEAD000000010002;
/// @brief Indicates input reg0 is invalid
pub const BF_STATUS_INVALID_INPUT_REG0: u64 = 0xDEAD000000010003;
/// @brief Indicates input reg1 is invalid
pub const BF_STATUS_INVALID_INPUT_REG1: u64 = 0xDEAD000000020003;
/// @brief Indicates input reg2 is invalid
pub const BF_STATUS_INVALID_INPUT_REG2: u64 = 0xDEAD000000040003;
/// @brief Indicates input reg3 is invalid
pub const BF_STATUS_INVALID_INPUT_REG3: u64 = 0xDEAD000000080003;
/// @brief Indicates input reg4 is invalid
pub const BF_STATUS_INVALID_INPUT_REG4: u64 = 0xDEAD000000100003;
/// @brief Indicates input reg5 is invalid
pub const BF_STATUS_INVALID_INPUT_REG5: u64 = 0xDEAD000000200003;
/// @brief Indicates output reg0 is invalid
pub const BF_STATUS_INVALID_OUTPUT_REG0: u64 = 0xDEAD000000400003;
/// @brief Indicates output reg1 is invalid
pub const BF_STATUS_INVALID_OUTPUT_REG1: u64 = 0xDEAD000000800003;
/// @brief Indicates output reg2 is invalid
pub const BF_STATUS_INVALID_OUTPUT_REG2: u64 = 0xDEAD000001000003;
/// @brief Indicates output reg3 is invalid
pub const BF_STATUS_INVALID_OUTPUT_REG3: u64 = 0xDEAD000002000003;
/// @brief Indicates output reg4 is invalid
pub const BF_STATUS_INVALID_OUTPUT_REG4: u64 = 0xDEAD000004000003;
/// @brief Indicates output reg5 is invalid
pub const BF_STATUS_INVALID_OUTPUT_REG5: u64 = 0xDEAD000008000003;

// -------------------------------------------------------------------------
// Syscall Inputs
// -------------------------------------------------------------------------

/// @brief Defines the BF_SYSCALL_SIG field for RAX
pub const BF_SYSCALL_SIG_VAL: u64 = 0x6642000000000000;
/// @brief Defines a mask for BF_SYSCALL_SIG
pub const BF_SYSCALL_SIG_MASK: u64 = 0xFFFF000000000000;
/// @brief Defines a mask for BF_SYSCALL_FLAGS
pub const BF_SYSCALL_FLAGS_MASK: u64 = 0x0000FFFF00000000;
/// @brief Defines a mask for BF_SYSCALL_OP
pub const BF_SYSCALL_OPCODE_MASK: u64 = 0xFFFF0000FFFF0000;
/// @brief Defines a mask for BF_SYSCALL_OP (with no signature added)
pub const BF_SYSCALL_OPCODE_NOSIG_MASK: u64 = 0x00000000FFFF0000;
/// @brief Defines a mask for BF_SYSCALL_IDX
pub const BF_SYSCALL_INDEX_MASK: u64 = 0x000000000000FFFF;

/// <!-- description -->
///   @brief n/a
///
/// <!-- inputs/outputs -->
///   @param rax n/a
///   @return n/a
///
pub fn bf_syscall_sig(rax: u64) -> u64 {
    return rax & BF_SYSCALL_SIG_MASK;
}

#[cfg(test)]
mod test_bf_syscall_sig {
    #[test]
    fn test_bf_syscall_sig() {
        let syscall: u64 = 0x1234567890ABCDEF;
        let expected: u64 = 0x1234000000000000;
        assert_eq!(super::bf_syscall_sig(syscall), expected);
    }
}

/// <!-- description -->
///   @brief n/a
///
/// <!-- inputs/outputs -->
///   @param rax n/a
///   @return n/a
///
pub fn bf_syscall_flags(rax: u64) -> u64 {
    return rax & BF_SYSCALL_FLAGS_MASK;
}

#[cfg(test)]
mod test_bf_syscall_flags {
    #[test]
    fn test_bf_syscall_flags() {
        let syscall: u64 = 0x1234567890ABCDEF;
        let expected: u64 = 0x0000567800000000;
        assert_eq!(super::bf_syscall_flags(syscall), expected);
    }
}

/// <!-- description -->
///   @brief n/a
///
/// <!-- inputs/outputs -->
///   @param rax n/a
///   @return n/a
///
pub fn bf_syscall_opcode(rax: u64) -> u64 {
    return rax & BF_SYSCALL_OPCODE_MASK;
}

#[cfg(test)]
mod test_bf_syscall_opcode {
    #[test]
    fn test_bf_syscall_opcode() {
        let syscall: u64 = 0x1234567890ABCDEF;
        let expected: u64 = 0x1234000090AB0000;
        assert_eq!(super::bf_syscall_opcode(syscall), expected);
    }
}

/// <!-- description -->
///   @brief n/a
///
/// <!-- inputs/outputs -->
///   @param rax n/a
///   @return n/a
///
pub fn bf_syscall_opcode_nosig(rax: u64) -> u64 {
    return rax & BF_SYSCALL_OPCODE_NOSIG_MASK;
}

#[cfg(test)]
mod test_bf_syscall_opcode_nosig {
    #[test]
    fn test_bf_syscall_opcode_nosig() {
        let syscall: u64 = 0x1234567890ABCDEF;
        let expected: u64 = 0x0000000090AB0000;
        assert_eq!(super::bf_syscall_opcode_nosig(syscall), expected);
    }
}

/// <!-- description -->
///   @brief n/a
///
/// <!-- inputs/outputs -->
///   @param rax n/a
///   @return n/a
///
pub fn bf_syscall_index(rax: u64) -> u64 {
    return rax & BF_SYSCALL_INDEX_MASK;
}

#[cfg(test)]
mod test_bf_syscall_index {
    #[test]
    fn test_bf_syscall_index() {
        let syscall: u64 = 0x1234567890ABCDEF;
        let expected: u64 = 0x000000000000CDEF;
        assert_eq!(super::bf_syscall_index(syscall), expected);
    }
}

// -------------------------------------------------------------------------
// Specification IDs
// -------------------------------------------------------------------------

/// @brief Defines the ID for version #1 of this spec
pub const BF_SPEC_ID1_VAL: u32 = 0x31236642;

/// @brief Defines the mask for checking support for version #1 of this spec
pub const BF_SPEC_ID1_MASK: u32 = 0x2;

/// @brief Defines all versions supported
pub const BF_ALL_SPECS_SUPPORTED_VAL: u32 = 0x2;

/// @brief Defines an invalid version
pub const BF_INVALID_VERSION: u32 = 0x80000000;

/// <!-- description -->
///   @brief n/a
///
/// <!-- inputs/outputs -->
///   @param version n/a
///   @return n/a
///
pub fn bf_is_spec1_supported(version: u32) -> bool {
    return (version & BF_SPEC_ID1_MASK) != 0;
}

#[cfg(test)]
mod test_bf_is_spec1_supported {
    #[test]
    fn test_bf_is_spec1_supported() {
        let ver1: u32 = 0x2;
        let ver2: u32 = 0x80000000;
        assert!(super::bf_is_spec1_supported(ver1));
        assert!(!super::bf_is_spec1_supported(ver2));
    }
}

// -------------------------------------------------------------------------
// Syscall Opcodes - Control Support
// -------------------------------------------------------------------------

/// @brief Defines the syscall opcode for bf_control_op
pub const BF_CONTROL_OP_VAL: u64 = 0x6642000000000000;
/// @brief Defines the syscall opcode for bf_control_op (nosig)
pub const BF_CONTROL_OP_NOSIG_VAL: u64 = 0x0000000000000000;

// -------------------------------------------------------------------------
// Syscall Opcodes - Handle Support
// -------------------------------------------------------------------------

/// @brief Defines the syscall opcode for bf_handle_op
pub const BF_HANDLE_OP_VAL: u64 = 0x6642000000010000;
/// @brief Defines the syscall opcode for bf_handle_op (nosig)
pub const BF_HANDLE_OP_NOSIG_VAL: u64 = 0x0000000000010000;

// -------------------------------------------------------------------------
// Syscall Opcodes - Debug Support
// -------------------------------------------------------------------------

/// @brief Defines the syscall opcode for bf_debug_op
pub const BF_DEBUG_OP_VAL: u64 = 0x6642000000020000;
/// @brief Defines the syscall opcode for bf_debug_op (nosig)
pub const BF_DEBUG_OP_NOSIG_VAL: u64 = 0x00000000000020000;

// -------------------------------------------------------------------------
// Syscall Opcodes - Callback Support
// -------------------------------------------------------------------------

/// @brief Defines the syscall opcode for bf_callback_op
pub const BF_CALLBACK_OP_VAL: u64 = 0x6642000000030000;
/// @brief Defines the syscall opcode for bf_callback_op (nosig)
pub const BF_CALLBACK_OP_NOSIG_VAL: u64 = 0x0000000000030000;

// -------------------------------------------------------------------------
// Syscall Opcodes - VM Support
// -------------------------------------------------------------------------

/// @brief Defines the syscall opcode for bf_vm_op
pub const BF_VM_OP_VAL: u64 = 0x6642000000040000;
/// @brief Defines the syscall opcode for bf_vm_op (nosig)
pub const BF_VM_OP_NOSIG_VAL: u64 = 0x0000000000040000;

// -------------------------------------------------------------------------
// Syscall Opcodes - VP Support
// -------------------------------------------------------------------------

/// @brief Defines the syscall opcode for bf_vp_op
pub const BF_VP_OP_VAL: u64 = 0x6642000000050000;
/// @brief Defines the syscall opcode for bf_vp_op (nosig)
pub const BF_VP_OP_NOSIG_VAL: u64 = 0x0000000000050000;

// -------------------------------------------------------------------------
// Syscall Opcodes - VS Support
// -------------------------------------------------------------------------

/// @brief Defines the syscall opcode for bf_vs_op
pub const BF_VS_OP_VAL: u64 = 0x6642000000060000;
/// @brief Defines the syscall opcode for bf_vs_op (nosig)
pub const BF_VS_OP_NOSIG_VAL: u64 = 0x0000000000060000;

// -------------------------------------------------------------------------
// Syscall Opcodes - Intrinsic Support
// -------------------------------------------------------------------------

/// @brief Defines the syscall opcode for bf_intrinsic_op
pub const BF_INTRINSIC_OP_VAL: u64 = 0x6642000000070000;
/// @brief Defines the syscall opcode for bf_intrinsic_op (nosig)
pub const BF_INTRINSIC_OP_NOSIG_VAL: u64 = 0x0000000000070000;

// -------------------------------------------------------------------------
// Syscall Opcodes - Mem Support
// -------------------------------------------------------------------------

/// @brief Defines the syscall opcode for bf_mem_op
pub const BF_MEM_OP_VAL: u64 = 0x6642000000080000;
/// @brief Defines the syscall opcode for bf_mem_op (nosig)
pub const BF_MEM_OP_NOSIG_VAL: u64 = 0x0000000000080000;

// -------------------------------------------------------------------------
// TLS Offsets
// -------------------------------------------------------------------------

/// @brief stores the offset for rax
pub const TLS_OFFSET_RAX: u64 = 0x800;
/// @brief stores the offset for rbx
pub const TLS_OFFSET_RBX: u64 = 0x808;
/// @brief stores the offset for rcx
pub const TLS_OFFSET_RCX: u64 = 0x810;
/// @brief stores the offset for rdx
pub const TLS_OFFSET_RDX: u64 = 0x818;
/// @brief stores the offset for rbp
pub const TLS_OFFSET_RBP: u64 = 0x820;
/// @brief stores the offset for rsi
pub const TLS_OFFSET_RSI: u64 = 0x828;
/// @brief stores the offset for rdi
pub const TLS_OFFSET_RDI: u64 = 0x830;
/// @brief stores the offset for r8
pub const TLS_OFFSET_R8: u64 = 0x838;
/// @brief stores the offset for r9
pub const TLS_OFFSET_R9: u64 = 0x840;
/// @brief stores the offset for r10
pub const TLS_OFFSET_R10: u64 = 0x848;
/// @brief stores the offset for r11
pub const TLS_OFFSET_R11: u64 = 0x850;
/// @brief stores the offset for r12
pub const TLS_OFFSET_R12: u64 = 0x858;
/// @brief stores the offset for r13
pub const TLS_OFFSET_R13: u64 = 0x860;
/// @brief stores the offset for r14
pub const TLS_OFFSET_R14: u64 = 0x868;
/// @brief stores the offset for r15
pub const TLS_OFFSET_R15: u64 = 0x870;
/// @brief stores the offset of the active extid
pub const TLS_OFFSET_ACTIVE_EXTID: u64 = 0xFF0;
/// @brief stores the offset of the active vmid
pub const TLS_OFFSET_ACTIVE_VMID: u64 = 0xFF2;
/// @brief stores the offset of the active vpid
pub const TLS_OFFSET_ACTIVE_VPID: u64 = 0xFF4;
/// @brief stores the offset of the active vsid
pub const TLS_OFFSET_ACTIVE_VSID: u64 = 0xFF6;
/// @brief stores the offset of the active ppid
pub const TLS_OFFSET_ACTIVE_PPID: u64 = 0xFF8;
/// @brief stores the number of PPs that are online
pub const TLS_OFFSET_ONLINE_PPS: u64 = 0xFFA;

// -------------------------------------------------------------------------
// Hypercall Related Constants
// -------------------------------------------------------------------------

/// @brief Defines an invalid handle
pub const BF_INVALID_HANDLE: u64 = 0xFFFFFFFFFFFFFFFF;

// -------------------------------------------------------------------------
// Syscall Indexes
// -------------------------------------------------------------------------

/// @brief Defines the index for bf_control_op_exit
pub const BF_CONTROL_OP_EXIT_IDX_VAL: u64 = 0x0000000000000000;
/// @brief Defines the index for bf_control_op_wait
pub const BF_CONTROL_OP_WAIT_IDX_VAL: u64 = 0x0000000000000001;

/// @brief Defines the index for bf_handle_op_open_handle
pub const BF_HANDLE_OP_OPEN_HANDLE_IDX_VAL: u64 = 0x0000000000000000;
/// @brief Defines the index for bf_handle_op_close_handle
pub const BF_HANDLE_OP_CLOSE_HANDLE_IDX_VAL: u64 = 0x0000000000000001;

/// @brief Defines the index for bf_debug_op_out
pub const BF_DEBUG_OP_OUT_IDX_VAL: u64 = 0x0000000000000000;
/// @brief Defines the index for bf_debug_op_dump_vm
pub const BF_DEBUG_OP_DUMP_VM_IDX_VAL: u64 = 0x0000000000000001;
/// @brief Defines the index for bf_debug_op_dump_vp
pub const BF_DEBUG_OP_DUMP_VP_IDX_VAL: u64 = 0x0000000000000002;
/// @brief Defines the index for bf_debug_op_dump_vs
pub const BF_DEBUG_OP_DUMP_VS_IDX_VAL: u64 = 0x0000000000000003;
/// @brief Defines the index for bf_debug_op_dump_vmexit_log
pub const BF_DEBUG_OP_DUMP_VMEXIT_LOG_IDX_VAL: u64 = 0x0000000000000004;
/// @brief Defines the index for bf_debug_op_write_c
pub const BF_DEBUG_OP_WRITE_C_IDX_VAL: u64 = 0x0000000000000005;
/// @brief Defines the index for bf_debug_op_write_str
pub const BF_DEBUG_OP_WRITE_STR_IDX_VAL: u64 = 0x0000000000000006;
/// @brief Defines the index for bf_debug_op_dump_ext
pub const BF_DEBUG_OP_DUMP_EXT_IDX_VAL: u64 = 0x0000000000000007;
/// @brief Defines the index for bf_debug_op_dump_page_pool
pub const BF_DEBUG_OP_DUMP_PAGE_POOL_IDX_VAL: u64 = 0x0000000000000008;
/// @brief Defines the index for bf_debug_op_dump_huge_pool
pub const BF_DEBUG_OP_DUMP_HUGE_POOL_IDX_VAL: u64 = 0x0000000000000009;

/// @brief Defines the index for bf_callback_op_register_bootstrap
pub const BF_CALLBACK_OP_REGISTER_BOOTSTRAP_IDX_VAL: u64 = 0x0000000000000000;
/// @brief Defines the index for bf_callback_op_register_vmexit
pub const BF_CALLBACK_OP_REGISTER_VMEXIT_IDX_VAL: u64 = 0x0000000000000001;
/// @brief Defines the index for bf_callback_op_register_fail
pub const BF_CALLBACK_OP_REGISTER_FAIL_IDX_VAL: u64 = 0x0000000000000002;

/// @brief Defines the index for bf_vm_op_create_vm
pub const BF_VM_OP_CREATE_VM_IDX_VAL: u64 = 0x0000000000000000;
/// @brief Defines the index for bf_vm_op_destroy_vm
pub const BF_VM_OP_DESTROY_VM_IDX_VAL: u64 = 0x0000000000000001;
/// @brief Defines the index for bf_vm_op_map_direct
pub const BF_VM_OP_MAP_DIRECT_IDX_VAL: u64 = 0x0000000000000002;
/// @brief Defines the index for bf_vm_op_unmap_direct
pub const BF_VM_OP_UNMAP_DIRECT_IDX_VAL: u64 = 0x0000000000000003;
/// @brief Defines the index for bf_vm_op_unmap_direct_broadcast
pub const BF_VM_OP_UNMAP_DIRECT_BROADCAST_IDX_VAL: u64 = 0x0000000000000004;

/// @brief Defines the index for bf_vp_op_create_vp
pub const BF_VP_OP_CREATE_VP_IDX_VAL: u64 = 0x0000000000000000;
/// @brief Defines the index for bf_vp_op_destroy_vp
pub const BF_VP_OP_DESTROY_VP_IDX_VAL: u64 = 0x0000000000000001;

/// @brief Defines the index for bf_vs_op_create_vs
pub const BF_VS_OP_CREATE_VS_IDX_VAL: u64 = 0x0000000000000000;
/// @brief Defines the index for bf_vs_op_destroy_vs
pub const BF_VS_OP_DESTROY_VS_IDX_VAL: u64 = 0x0000000000000001;
/// @brief Defines the index for bf_vs_op_init_as_root
pub const BF_VS_OP_INIT_AS_ROOT_IDX_VAL: u64 = 0x0000000000000002;
/// @brief Defines the index for bf_vs_op_read_reg
pub const BF_VS_OP_READ_IDX_VAL: u64 = 0x0000000000000003;
/// @brief Defines the index for bf_vs_op_write_reg
pub const BF_VS_OP_WRITE_IDX_VAL: u64 = 0x0000000000000004;
/// @brief Defines the index for bf_vs_op_run
pub const BF_VS_OP_RUN_IDX_VAL: u64 = 0x0000000000000005;
/// @brief Defines the index for bf_vs_op_run_current
pub const BF_VS_OP_RUN_CURRENT_IDX_VAL: u64 = 0x0000000000000006;
/// @brief Defines the index for bf_vs_op_advance_ip_and_run
pub const BF_VS_OP_ADVANCE_IP_AND_RUN_IDX_VAL: u64 = 0x0000000000000007;
/// @brief Defines the index for bf_vs_op_advance_ip_and_run_current
pub const BF_VS_OP_ADVANCE_IP_AND_RUN_CURRENT_IDX_VAL: u64 = 0x0000000000000008;
/// @brief Defines the index for bf_vs_op_promote
pub const BF_VS_OP_PROMOTE_IDX_VAL: u64 = 0x0000000000000009;
/// @brief Defines the index for bf_vs_op_clear
pub const BF_VS_OP_CLEAR_IDX_VAL: u64 = 0x000000000000000A;
/// @brief Defines the index for bf_vs_op_migrate
pub const BF_VS_OP_MIGRATE_IDX_VAL: u64 = 0x000000000000000B;
/// @brief Defines the index for bf_vs_op_set_active
pub const BF_VS_OP_SET_ACTIVE_IDX_VAL: u64 = 0x000000000000000C;
/// @brief Defines the index for bf_vs_op_advance_ip_and_set_active
pub const BF_VS_OP_ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL: u64 = 0x000000000000000D;

/// @brief Defines the index for bf_intrinsic_op_rdmsr
pub const BF_INTRINSIC_OP_RDMSR_IDX_VAL: u64 = 0x0000000000000000;
/// @brief Defines the index for bf_intrinsic_op_wrmsr
pub const BF_INTRINSIC_OP_WRMSR_IDX_VAL: u64 = 0x0000000000000001;

/// @brief Defines the index for bf_mem_op_alloc_page
pub const BF_MEM_OP_ALLOC_PAGE_IDX_VAL: u64 = 0x0000000000000000;
/// @brief Defines the index for bf_mem_op_free_page
pub const BF_MEM_OP_FREE_PAGE_IDX_VAL: u64 = 0x0000000000000001;
/// @brief Defines the index for bf_mem_op_alloc_huge
pub const BF_MEM_OP_ALLOC_HUGE_IDX_VAL: u64 = 0x0000000000000002;
/// @brief Defines the index for bf_mem_op_free_huge
pub const BF_MEM_OP_FREE_HUGE_IDX_VAL: u64 = 0x0000000000000003;
