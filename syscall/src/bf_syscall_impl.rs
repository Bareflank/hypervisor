use crate::types::BfCharT;
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
use crate::types::BfCptrT;
use crate::types::BfCstrT;

extern "C" {

    // -------------------------------------------------------------------------
    // TLS ops
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rax.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    pub fn bf_tls_rax_impl() -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rax.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    pub fn bf_tls_set_rax_impl(val: u64);

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rbx.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    pub fn bf_tls_rbx_impl() -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rbx.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    pub fn bf_tls_set_rbx_impl(val: u64);

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rcx.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    pub fn bf_tls_rcx_impl() -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rcx.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    pub fn bf_tls_set_rcx_impl(val: u64);

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rdx.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    pub fn bf_tls_rdx_impl() -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rdx.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    pub fn bf_tls_set_rdx_impl(val: u64);

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rbp.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    pub fn bf_tls_rbp_impl() -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rbp.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    pub fn bf_tls_set_rbp_impl(val: u64);

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rsi.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    pub fn bf_tls_rsi_impl() -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rsi.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    pub fn bf_tls_set_rsi_impl(val: u64);

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rdi.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    pub fn bf_tls_rdi_impl() -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rdi.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    pub fn bf_tls_set_rdi_impl(val: u64);

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r8.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    pub fn bf_tls_r8_impl() -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r8.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    pub fn bf_tls_set_r8_impl(val: u64);

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r9.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    pub fn bf_tls_r9_impl() -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r9.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    pub fn bf_tls_set_r9_impl(val: u64);

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r10.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    pub fn bf_tls_r10_impl() -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r10.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    pub fn bf_tls_set_r10_impl(val: u64);

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r11.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    pub fn bf_tls_r11_impl() -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r11.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    pub fn bf_tls_set_r11_impl(val: u64);

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r12.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    pub fn bf_tls_r12_impl() -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r12.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    pub fn bf_tls_set_r12_impl(val: u64);

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r13.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    pub fn bf_tls_r13_impl() -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r13.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    pub fn bf_tls_set_r13_impl(val: u64);

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r14.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    pub fn bf_tls_r14_impl() -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r14.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    pub fn bf_tls_set_r14_impl(val: u64);

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r15.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    pub fn bf_tls_r15_impl() -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r15.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    pub fn bf_tls_set_r15_impl(val: u64);

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_extid.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    pub fn bf_tls_extid_impl() -> u16;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_vmid.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    pub fn bf_tls_vmid_impl() -> u16;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_vpid.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    pub fn bf_tls_vpid_impl() -> u16;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_vsid.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    pub fn bf_tls_vsid_impl() -> u16;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_ppid.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    pub fn bf_tls_ppid_impl() -> u16;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_online_pps.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    pub fn bf_tls_online_pps_impl() -> u16;

    // -------------------------------------------------------------------------
    // bf_control_ops
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_control_op_exit.
    ///
    pub fn bf_control_op_exit_impl();

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_control_op_wait.
    ///
    pub fn bf_control_op_wait_impl();

    // -------------------------------------------------------------------------
    // bf_handle_ops
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_handle_op_open_handle.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg0_out n/a
    ///   @return n/a
    ///
    pub fn bf_handle_op_open_handle_impl(reg0_in: u32, reg0_out: *mut u64) -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_handle_op_close_handle.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @return n/a
    ///
    pub fn bf_handle_op_close_handle_impl(reg0_in: u64) -> u64;

    // -------------------------------------------------------------------------
    // bf_debug_ops
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_out.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///
    pub fn bf_debug_op_out_impl(reg0_in: u64, reg1_in: u64);

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_dump_vm.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    pub fn bf_debug_op_dump_vm_impl(reg0_in: u16);

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_dump_vp.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    pub fn bf_debug_op_dump_vp_impl(reg0_in: u16);

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_dump_vs.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    pub fn bf_debug_op_dump_vs_impl(reg0_in: u16);

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_dump_vmexit_log.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    pub fn bf_debug_op_dump_vmexit_log_impl(reg0_in: u16);

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_write_c.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    pub fn bf_debug_op_write_c_impl(reg0_in: BfCharT);

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_write_str.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    pub fn bf_debug_op_write_str_impl(reg0_in: BfCstrT);

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_dump_ext.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    pub fn bf_debug_op_dump_ext_impl(reg0_in: u16);

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_dump_page_pool.
    ///
    pub fn bf_debug_op_dump_page_pool_impl();

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_dump_huge_pool.
    ///
    pub fn bf_debug_op_dump_huge_pool_impl();

    // -------------------------------------------------------------------------
    // bf_callback_ops
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_callback_op_register_bootstrap.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    pub fn bf_callback_op_register_bootstrap_impl(reg0_in: u64, reg1_in: BfCptrT) -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_callback_op_register_vmexit.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    pub fn bf_callback_op_register_vmexit_impl(reg0_in: u64, reg1_in: BfCptrT) -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_callback_op_register_fail.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    pub fn bf_callback_op_register_fail_impl(reg0_in: u64, reg1_in: BfCptrT) -> u64;

    // -------------------------------------------------------------------------
    // bf_vm_ops
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vm_op_create_vm.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg0_out n/a
    ///   @return n/a
    ///
    pub fn bf_vm_op_create_vm_impl(reg0_in: u64, reg0_out: *mut u16) -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vm_op_destroy_vm.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    pub fn bf_vm_op_destroy_vm_impl(reg0_in: u64, reg1_in: u16) -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vm_op_map_direct.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @param reg0_out n/a
    ///   @return n/a
    ///
    pub fn bf_vm_op_map_direct_impl(
        reg0_in: u64,
        reg1_in: u16,
        reg2_in: u64,
        reg0_out: *mut BfCptrT,
    ) -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vm_op_unmap_direct.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @return n/a
    ///
    pub fn bf_vm_op_unmap_direct_impl(reg0_in: u64, reg1_in: u16, reg2_in: u64) -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vm_op_unmap_direct_broadcast.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @return n/a
    ///
    pub fn bf_vm_op_unmap_direct_broadcast_impl(reg0_in: u64, reg1_in: u16, reg2_in: u64) -> u64;

    // -------------------------------------------------------------------------
    // bf_vp_ops
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vp_op_create_vp.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @param reg0_out n/a
    ///   @return n/a
    ///
    pub fn bf_vp_op_create_vp_impl(
        reg0_in: u64,
        reg1_in: u16,
        reg2_in: u16,
        reg0_out: *mut u16,
    ) -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vp_op_destroy_vp.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    pub fn bf_vp_op_destroy_vp_impl(reg0_in: u64, reg1_in: u16) -> u64;

    // -------------------------------------------------------------------------
    // bf_vs_ops
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vs_op_create_vs.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @param reg0_out n/a
    ///   @return n/a
    ///
    pub fn bf_vs_op_create_vs_impl(
        reg0_in: u64,
        reg1_in: u16,
        reg2_in: u16,
        reg0_out: *mut u16,
    ) -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vs_op_destroy_vs.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    pub fn bf_vs_op_destroy_vs_impl(reg0_in: u64, reg1_in: u16) -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vs_op_init_as_root.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    pub fn bf_vs_op_init_as_root_impl(reg0_in: u64, reg1_in: u16) -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vs_op_read_impl.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @param reg0_out n/a
    ///   @return n/a
    ///
    pub fn bf_vs_op_read_impl(
        reg0_in: u64,
        reg1_in: u16,
        reg2_in: u64,
        reg0_out: *const u64,
    ) -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vs_op_write.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @param reg3_in n/a
    ///   @return n/a
    ///
    pub fn bf_vs_op_write_impl(reg0_in: u64, reg1_in: u16, reg2_in: u64, reg3_in: u64) -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vs_op_run.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @param reg3_in n/a
    ///   @return n/a
    ///
    pub fn bf_vs_op_run_impl(reg0_in: u64, reg1_in: u16, reg2_in: u16, reg3_in: u16) -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vs_op_run_current.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @return n/a
    ///
    pub fn bf_vs_op_run_current_impl(reg0_in: u64) -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vs_op_advance_ip.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    pub fn bf_vs_op_advance_ip_impl(reg0_in: u64, reg1_in: u16) -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vs_op_advance_ip_and_run_current.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @return n/a
    ///
    pub fn bf_vs_op_advance_ip_and_run_current_impl(reg0_in: u64) -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vs_op_promote.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    pub fn bf_vs_op_promote_impl(reg0_in: u64, reg1_in: u16) -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vs_op_clear.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    pub fn bf_vs_op_clear_impl(reg0_in: u64, reg1_in: u16) -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vs_op_migrate.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @return n/a
    ///
    pub fn bf_vs_op_migrate_impl(reg0_in: u64, reg1_in: u16, reg2_in: u16) -> u64;

    // -------------------------------------------------------------------------
    // bf_intrinsic_ops
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_intrinsic_op_rdmsr.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg0_out n/a
    ///   @return n/a
    ///
    pub fn bf_intrinsic_op_rdmsr_impl(reg0_in: u64, reg1_in: u32, reg0_out: *const u64) -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_intrinsic_op_wrmsr.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @return n/a
    ///
    pub fn bf_intrinsic_op_wrmsr_impl(reg0_in: u64, reg1_in: u32, reg2_in: u64) -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_intrinsic_op_invlpga.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @return n/a
    ///
    pub fn bf_intrinsic_op_invlpga_impl(reg0_in: u64, reg1_in: u64, reg2_in: u64) -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_intrinsic_op_invept.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @return n/a
    ///
    pub fn bf_intrinsic_op_invept_impl(reg0_in: u64, reg1_in: u64, reg2_in: u64) -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_intrinsic_op_invvpid.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @param reg3_in n/a
    ///   @return n/a
    ///
    pub fn bf_intrinsic_op_invvpid_impl(
        reg0_in: u64,
        reg1_in: u64,
        reg2_in: u16,
        reg3_in: u64,
    ) -> u64;

    // -------------------------------------------------------------------------
    // bf_mem_ops
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_mem_op_alloc_page.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg0_out n/a
    ///   @param reg1_out n/a
    ///   @return n/a
    ///
    pub fn bf_mem_op_alloc_page_impl(
        reg0_in: u64,
        reg0_out: *mut BfCptrT,
        reg1_out: *const u64,
    ) -> u64;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_mem_op_alloc_huge.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg0_out n/a
    ///   @param reg1_out n/a
    ///   @return n/a
    ///
    pub fn bf_mem_op_alloc_huge_impl(
        reg0_in: u64,
        reg1_in: u64,
        reg0_out: *mut BfCptrT,
        reg1_out: *const u64,
    ) -> u64;
}
