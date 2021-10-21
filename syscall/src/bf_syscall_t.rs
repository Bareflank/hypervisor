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

#[derive(Debug, Default, Copy, Clone, PartialEq, PartialOrd)]
pub struct BfSyscallT {
    m_hndl: bsl::SafeU64,
}

impl BfSyscallT {
    /// <!-- description -->
    ///   @brief New constructor
    ///
    pub const fn new() -> Self {
        Self {
            m_hndl: crate::BF_INVALID_HANDLE,
        }
    }

    /// <!-- inputs/outputs -->
    ///   @param version the version provided to the extension by the
    ///     microkernel. If this API does not support the ABI versions
    ///     that the microkernel supports, this function will fail.
    ///   @param pmut_bootstrap_handler the bootstrap handler to register
    ///   @param pmut_vmexit_handler the vmexit handler to register
    ///   @param pmut_fail_handler the fail handler to register
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    pub fn initialize(
        &mut self,
        version: bsl::SafeU32,
        pmut_bootstrap_handler: bsl::CPtrT,
        pmut_vmexit_handler: bsl::CPtrT,
        pmut_fail_handler: bsl::CPtrT,
    ) -> bsl::ErrcType {
        let mut ret: u64;
        bsl::expects(version.is_valid_and_checked());
        bsl::expects(version.is_pos());
        bsl::expects(core::ptr::null() != pmut_bootstrap_handler);
        bsl::expects(core::ptr::null() != pmut_vmexit_handler);
        bsl::expects(core::ptr::null() != pmut_fail_handler);

        if !crate::bf_is_spec1_supported(version) {
            error!("unsupported microkernel {:#018x}\n{}", version, bsl::here());
            return bsl::errc_unsupported;
        }

        unsafe {
            ret = crate::bf_handle_op_open_handle_impl(
                crate::BF_SPEC_ID1_VAL.get(),
                self.m_hndl.data(),
            );
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_handle_op_open_handle_impl failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return bsl::errc_failure;
        }

        unsafe {
            ret = crate::bf_callback_op_register_bootstrap_impl(
                self.m_hndl.get(),
                pmut_bootstrap_handler,
            );
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_callback_op_register_bootstrap failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            self.release();
            return bsl::errc_failure;
        }

        unsafe {
            ret =
                crate::bf_callback_op_register_vmexit_impl(self.m_hndl.get(), pmut_vmexit_handler);
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_callback_op_register_vmexit failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            self.release();
            return bsl::errc_failure;
        }

        unsafe {
            ret = crate::bf_callback_op_register_fail_impl(self.m_hndl.get(), pmut_fail_handler);
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_callback_op_register_fail failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            self.release();
            return bsl::errc_failure;
        }

        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief Releases the BfSyscallT by closing the handle.
    ///
    pub fn release(&mut self) {
        unsafe {
            crate::bf_handle_op_close_handle_impl(self.m_hndl.get());
        }

        self.m_hndl = bsl::SafeU64::magic_0();
    }

    /// <!-- description -->
    ///   @brief Returns the handle that is used for syscalls. If this
    ///     class has not been initialized, a default (likely 0) handle
    ///     is returned.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the handle that is used for syscalls. If this
    ///     class has not been initialized, a default (likely 0) handle
    ///     is returned.
    ///
    pub fn handle(&self) -> bsl::SafeU64 {
        return self.m_hndl;
    }

    // ---------------------------------------------------------------------
    // TLS ops
    // ---------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Returns the value of tls.rax
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the value of tls.rax
    ///
    pub fn bf_tls_rax() -> bsl::SafeU64 {
        unsafe {
            return bsl::to_u64(crate::bf_tls_rax_impl());
        }
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.rax
    ///
    /// <!-- inputs/outputs -->
    ///   @param val The value to set tls.rax to
    ///
    pub fn bf_tls_set_rax(val: bsl::SafeU64) {
        bsl::expects(val.is_valid_and_checked());
        unsafe {
            crate::bf_tls_set_rax_impl(val.get());
        }
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.rbx
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the value of tls.rbx
    ///
    pub fn bf_tls_rbx() -> bsl::SafeU64 {
        unsafe {
            return bsl::to_u64(crate::bf_tls_rbx_impl());
        }
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.rbx
    ///
    /// <!-- inputs/outputs -->
    ///   @param val The value to set tls.rbx to
    ///
    pub fn bf_tls_set_rbx(val: bsl::SafeU64) {
        bsl::expects(val.is_valid_and_checked());
        unsafe {
            crate::bf_tls_set_rbx_impl(val.get());
        }
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.rcx
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the value of tls.rcx
    ///
    pub fn bf_tls_rcx() -> bsl::SafeU64 {
        unsafe {
            return bsl::to_u64(crate::bf_tls_rcx_impl());
        }
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.rcx
    ///
    /// <!-- inputs/outputs -->
    ///   @param val The value to set tls.rcx to
    ///
    pub fn bf_tls_set_rcx(val: bsl::SafeU64) {
        bsl::expects(val.is_valid_and_checked());
        unsafe {
            crate::bf_tls_set_rcx_impl(val.get());
        }
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.rdx
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the value of tls.rdx
    ///
    pub fn bf_tls_rdx() -> bsl::SafeU64 {
        unsafe {
            return bsl::to_u64(crate::bf_tls_rdx_impl());
        }
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.rdx
    ///
    /// <!-- inputs/outputs -->
    ///   @param val The value to set tls.rdx to
    ///
    pub fn bf_tls_set_rdx(val: bsl::SafeU64) {
        bsl::expects(val.is_valid_and_checked());
        unsafe {
            crate::bf_tls_set_rdx_impl(val.get());
        }
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.rbp
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the value of tls.rbp
    ///
    pub fn bf_tls_rbp() -> bsl::SafeU64 {
        unsafe {
            return bsl::to_u64(crate::bf_tls_rbp_impl());
        }
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.rbp
    ///
    /// <!-- inputs/outputs -->
    ///   @param val The value to set tls.rbp to
    ///
    pub fn bf_tls_set_rbp(val: bsl::SafeU64) {
        bsl::expects(val.is_valid_and_checked());
        unsafe {
            crate::bf_tls_set_rbp_impl(val.get());
        }
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.rsi
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the value of tls.rsi
    ///
    pub fn bf_tls_rsi() -> bsl::SafeU64 {
        unsafe {
            return bsl::to_u64(crate::bf_tls_rsi_impl());
        }
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.rsi
    ///
    /// <!-- inputs/outputs -->
    ///   @param val The value to set tls.rsi to
    ///
    pub fn bf_tls_set_rsi(val: bsl::SafeU64) {
        bsl::expects(val.is_valid_and_checked());
        unsafe {
            crate::bf_tls_set_rsi_impl(val.get());
        }
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.rdi
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the value of tls.rdi
    ///
    pub fn bf_tls_rdi() -> bsl::SafeU64 {
        unsafe {
            return bsl::to_u64(crate::bf_tls_rdi_impl());
        }
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.rdi
    ///
    /// <!-- inputs/outputs -->
    ///   @param val The value to set tls.rdi to
    ///
    pub fn bf_tls_set_rdi(val: bsl::SafeU64) {
        bsl::expects(val.is_valid_and_checked());
        unsafe {
            crate::bf_tls_set_rdi_impl(val.get());
        }
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.r8
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the value of tls.r8
    ///
    pub fn bf_tls_r8() -> bsl::SafeU64 {
        unsafe {
            return bsl::to_u64(crate::bf_tls_r8_impl());
        }
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.r8
    ///
    /// <!-- inputs/outputs -->
    ///   @param val The value to set tls.r8 to
    ///
    pub fn bf_tls_set_r8(val: bsl::SafeU64) {
        bsl::expects(val.is_valid_and_checked());
        unsafe {
            crate::bf_tls_set_r8_impl(val.get());
        }
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.r9
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the value of tls.r9
    ///
    pub fn bf_tls_r9() -> bsl::SafeU64 {
        unsafe {
            return bsl::to_u64(crate::bf_tls_r9_impl());
        }
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.r9
    ///
    /// <!-- inputs/outputs -->
    ///   @param val The value to set tls.r9 to
    ///
    pub fn bf_tls_set_r9(val: bsl::SafeU64) {
        bsl::expects(val.is_valid_and_checked());
        unsafe {
            crate::bf_tls_set_r9_impl(val.get());
        }
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.r10
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the value of tls.r10
    ///
    pub fn bf_tls_r10() -> bsl::SafeU64 {
        unsafe {
            return bsl::to_u64(crate::bf_tls_r10_impl());
        }
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.r10
    ///
    /// <!-- inputs/outputs -->
    ///   @param val The value to set tls.r10 to
    ///
    pub fn bf_tls_set_r10(val: bsl::SafeU64) {
        bsl::expects(val.is_valid_and_checked());
        unsafe {
            crate::bf_tls_set_r10_impl(val.get());
        }
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.r11
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the value of tls.r11
    ///
    pub fn bf_tls_r11() -> bsl::SafeU64 {
        unsafe {
            return bsl::to_u64(crate::bf_tls_r11_impl());
        }
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.r11
    ///
    /// <!-- inputs/outputs -->
    ///   @param val The value to set tls.r11 to
    ///
    pub fn bf_tls_set_r11(val: bsl::SafeU64) {
        bsl::expects(val.is_valid_and_checked());
        unsafe {
            crate::bf_tls_set_r11_impl(val.get());
        }
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.r12
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the value of tls.r12
    ///
    pub fn bf_tls_r12() -> bsl::SafeU64 {
        unsafe {
            return bsl::to_u64(crate::bf_tls_r12_impl());
        }
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.r12
    ///
    /// <!-- inputs/outputs -->
    ///   @param val The value to set tls.r12 to
    ///
    pub fn bf_tls_set_r12(val: bsl::SafeU64) {
        bsl::expects(val.is_valid_and_checked());
        unsafe {
            crate::bf_tls_set_r12_impl(val.get());
        }
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.r13
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the value of tls.r13
    ///
    pub fn bf_tls_r13() -> bsl::SafeU64 {
        unsafe {
            return bsl::to_u64(crate::bf_tls_r13_impl());
        }
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.r13
    ///
    /// <!-- inputs/outputs -->
    ///   @param val The value to set tls.r13 to
    ///
    pub fn bf_tls_set_r13(val: bsl::SafeU64) {
        bsl::expects(val.is_valid_and_checked());
        unsafe {
            crate::bf_tls_set_r13_impl(val.get());
        }
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.r14
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the value of tls.r14
    ///
    pub fn bf_tls_r14() -> bsl::SafeU64 {
        unsafe {
            return bsl::to_u64(crate::bf_tls_r14_impl());
        }
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.r14
    ///
    /// <!-- inputs/outputs -->
    ///   @param val The value to set tls.r14 to
    ///
    pub fn bf_tls_set_r14(val: bsl::SafeU64) {
        bsl::expects(val.is_valid_and_checked());
        unsafe {
            crate::bf_tls_set_r14_impl(val.get());
        }
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.r15
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the value of tls.r15
    ///
    pub fn bf_tls_r15() -> bsl::SafeU64 {
        unsafe {
            return bsl::to_u64(crate::bf_tls_r15_impl());
        }
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.r15
    ///
    /// <!-- inputs/outputs -->
    ///   @param val The value to set tls.r15 to
    ///
    pub fn bf_tls_set_r15(val: bsl::SafeU64) {
        bsl::expects(val.is_valid_and_checked());
        unsafe {
            crate::bf_tls_set_r15_impl(val.get());
        }
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.extid
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the value of tls.extid
    ///
    pub fn bf_tls_extid() -> bsl::SafeU16 {
        unsafe {
            return bsl::to_u16(crate::bf_tls_extid_impl());
        }
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.vmid
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the value of tls.vmid
    ///
    pub fn bf_tls_vmid() -> bsl::SafeU16 {
        unsafe {
            return bsl::to_u16(crate::bf_tls_vmid_impl());
        }
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.vpid
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the value of tls.vpid
    ///
    pub fn bf_tls_vpid() -> bsl::SafeU16 {
        unsafe {
            return bsl::to_u16(crate::bf_tls_vpid_impl());
        }
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.vsid
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the value of tls.vsid
    ///
    pub fn bf_tls_vsid() -> bsl::SafeU16 {
        unsafe {
            return bsl::to_u16(crate::bf_tls_vsid_impl());
        }
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.ppid
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the value of tls.ppid
    ///
    pub fn bf_tls_ppid() -> bsl::SafeU16 {
        unsafe {
            return bsl::to_u16(crate::bf_tls_ppid_impl());
        }
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.online_pps
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the value of tls.online_pps
    ///
    pub fn bf_tls_online_pps() -> bsl::SafeU16 {
        unsafe {
            return bsl::to_u16(crate::bf_tls_online_pps_impl());
        }
    }

    /// <!-- description -->
    ///   @brief Returns true if the active VM is the
    ///     root VM. Returns false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the active VM is the
    ///     root VM. Returns false otherwise.
    ///
    pub fn is_the_active_vm_the_root_vm() -> bool {
        unsafe {
            return crate::BF_ROOT_VMID == crate::bf_tls_vmid_impl();
        }
    }

    /// <!-- description -->
    ///   @brief Returns true if the provided VMID is the
    ///     ID of the root VM. Returns false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vmid the ID of the VM to query
    ///   @return Returns true if the provided VMID is the
    ///     ID of the root VM. Returns false otherwise.
    ///
    pub fn is_vm_the_root_vm(vmid: bsl::SafeU16) -> bool {
        return vmid == crate::BF_ROOT_VMID;
    }

    /// <!-- description -->
    ///   @brief Returns true if the provided VPID is the
    ///     ID of a root VP. Returns false otherwise. This
    ///     is the same as vpid == sys.bf_tls_ppid().
    ///
    /// <!-- inputs/outputs -->
    ///   @param vpid the ID of the VP to query
    ///   @return Returns true if the provided VPID is the
    ///     ID of a root VP. Returns false otherwise. This
    ///     is the same as vpid == sys.bf_tls_ppid().
    ///
    pub fn is_vp_a_root_vp(vpid: bsl::SafeU16) -> bool {
        unsafe {
            return vpid < crate::bf_tls_online_pps_impl();
        }
    }

    /// <!-- description -->
    ///   @brief Returns true if the provided VSID is the
    ///     ID of a root VS. Returns false otherwise. This
    ///     is the same as vsid == sys.bf_tls_ppid().
    ///
    /// <!-- inputs/outputs -->
    ///   @param vsid the ID of the VS to query
    ///   @return Returns true if the provided VSID is the
    ///     ID of a root VS. Returns false otherwise. This
    ///     is the same as vsid == sys.bf_tls_ppid().
    ///
    pub fn is_vs_a_root_vs(vsid: bsl::SafeU16) -> bool {
        unsafe {
            return vsid < crate::bf_tls_online_pps_impl();
        }
    }

    // ---------------------------------------------------------------------
    // bf_vm_ops
    // ---------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to create a VM
    ///     and return it's ID.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the resulting ID, or bsl::SafeU16::failure()
    ///     on failure.
    ///
    pub fn bf_vm_op_create_vm(&self) -> bsl::SafeU16 {
        let ret: u64;
        let mut vmid: bsl::SafeU16 = bsl::SafeU16::default();

        unsafe {
            ret = crate::bf_vm_op_create_vm_impl(self.m_hndl.get(), vmid.data());
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_vm_op_create_vm failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return bsl::SafeU16::failure();
        }

        if crate::BF_INVALID_ID == vmid {
            error!(
                "the vmid {:#06x} returned by bf_vm_op_create_vm is invalid\n{}",
                vmid,
                bsl::here()
            );

            return bsl::SafeU16::failure();
        }

        if crate::HYPERVISOR_MAX_VMS <= bsl::to_umx(vmid) {
            error!(
                "the vmid {:#06x} returned by bf_vm_op_create_vm is out of range\n{}",
                vmid,
                bsl::here()
            );

            return bsl::SafeU16::failure();
        }

        return vmid;
    }

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to destroy a VM
    ///     given an ID.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vmid The ID of the VM to destroy
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    pub fn bf_vm_op_destroy_vm(&self, vmid: bsl::SafeU16) -> bsl::ErrcType {
        let ret: u64;

        bsl::expects(vmid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vmid);
        bsl::expects(crate::HYPERVISOR_MAX_VMS > bsl::to_umx(vmid));

        unsafe {
            ret = crate::bf_vm_op_destroy_vm_impl(self.m_hndl.get(), vmid.get());
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_vm_op_destroy_vm failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return bsl::errc_failure;
        }

        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to map a physical
    ///     address into the VM's direct map. This is the same as directly
    ///     accessing the direct map with the difference being that
    ///     software can provide a physical address and receive the
    ///     precalculated virtual address.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of pointer to return. Must be a POD type and
    ///     the size of a page.
    ///   @param vmid The ID of the VM to map the physical address to
    ///   @param phys The physical address to map
    ///   @return Returns a pointer to the map on success, returns a
    ///     nullptr on failure.
    ///
    pub fn bf_vm_op_map_direct<T>(&self, vmid: bsl::SafeU16, phys: bsl::SafeU64) -> *mut T {
        let ret: u64;
        let mut ptr: bsl::CPtrT = core::ptr::null_mut();

        bsl::expects(vmid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vmid);
        bsl::expects(crate::HYPERVISOR_MAX_VMS > bsl::to_umx(vmid));
        bsl::expects(phys.is_valid_and_checked());
        bsl::expects(phys.is_pos());
        bsl::expects(crate::HYPERVISOR_EXT_DIRECT_MAP_SIZE > phys);
        bsl::expects(crate::bf_is_page_aligned(phys));

        unsafe {
            ret = crate::bf_vm_op_map_direct_impl(
                self.m_hndl.get(),
                vmid.get(),
                phys.get(),
                &mut ptr,
            );
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_vm_op_destroy_vm failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return core::ptr::null_mut();
        }

        return ptr as *mut T;
    }

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to unmap a previously
    ///     mapped virtual address in the direct map. Unlike
    ///     bf_vm_op_unmap_direct_broadcast, this syscall does not flush the
    ///     TLB on any other PP, meaning this unmap is local to the PP the
    ///     call is made on. Attempting to unmap a virtual address from the
    ///     direct map that has been accessed on any other PP other than
    ///     the PP this syscall is executed on will result in undefined
    ///     behavior. This syscall is designed to support mapping and then
    ///     immediately unmapping a physical address on a single PP during
    ///     a single VMExit. It can also be used to map on a PP and then
    ///     use unmap on the same PP during multiple VMExits, but special
    ///     care must be taken to ensure no other PP can access the map,
    ///     otherwise UB will occur.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vmid The ID of the VM to unmap the virtual address from
    ///   @param ptr The virtual address to unmap
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    pub fn bf_vm_op_unmap_direct(&self, vmid: bsl::SafeU16, ptr: bsl::CPtrT) -> bsl::ErrcType {
        let ret: u64;

        bsl::expects(vmid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vmid);
        bsl::expects(crate::HYPERVISOR_MAX_VMS > bsl::to_umx(vmid));

        unsafe {
            ret = crate::bf_vm_op_unmap_direct_impl(self.m_hndl.get(), vmid.get(), ptr);
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_vm_op_unmap_direct failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return bsl::errc_failure;
        }

        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to unmap a previously
    ///     mapped virtual address in the direct map. Unlike
    ///     bf_vm_op_unmap_direct, this syscall performs a broadcast TLB flush
    ///     which means it can be safely used on all direct mapped
    ///     addresses. The downside of using this function is that it can
    ///     be a lot slower than bf_vm_op_unmap_direct, especially on
    ///     systems with a lot of PPs.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vmid The ID of the VM to unmap the virtual address from
    ///   @param ptr The virtual address to unmap
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    pub fn bf_vm_op_unmap_direct_broadcast(
        &self,
        vmid: bsl::SafeU16,
        ptr: bsl::CPtrT,
    ) -> bsl::ErrcType {
        let ret: u64;

        bsl::expects(vmid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vmid);
        bsl::expects(crate::HYPERVISOR_MAX_VMS > bsl::to_umx(vmid));

        unsafe {
            ret = crate::bf_vm_op_unmap_direct_broadcast_impl(self.m_hndl.get(), vmid.get(), ptr);
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_vm_op_unmap_direct_broadcast failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return bsl::errc_failure;
        }

        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief Given the ID of a VM, invalidates a TLB entry for a given
    ///     GLA on the PP that this is executed on.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vmid The ID of the VM to invalidate
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    pub fn bf_vm_op_tlb_flush(&self, vmid: bsl::SafeU16) -> bsl::ErrcType {
        let ret: u64;

        bsl::expects(vmid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vmid);
        bsl::expects(crate::HYPERVISOR_MAX_VMS > bsl::to_umx(vmid));

        unsafe {
            ret = crate::bf_vm_op_tlb_flush_impl(self.m_hndl.get(), vmid.get());
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_vm_op_tlb_flush failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return bsl::errc_failure;
        }

        return bsl::errc_success;
    }

    // ---------------------------------------------------------------------
    // bf_vp_ops
    // ---------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to create a VP given the
    ///     IDs of the VM and PP the VP will be assigned to. Upon success,
    ///     this syscall returns the ID of the newly created VP.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vmid The ID of the VM to assign the newly created VP to
    ///   @return Returns the resulting ID, or bsl::SafeU16::failure()
    ///     on failure.
    ///
    ///
    pub fn bf_vp_op_create_vp(&self, vmid: bsl::SafeU16) -> bsl::SafeU16 {
        let ret: u64;
        let mut vpid: bsl::SafeU16 = bsl::SafeU16::default();

        bsl::expects(vmid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vmid);
        bsl::expects(crate::HYPERVISOR_MAX_VPS > bsl::to_umx(vmid));

        unsafe {
            ret = crate::bf_vp_op_create_vp_impl(self.m_hndl.get(), vmid.get(), vpid.data());
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_vp_op_create_vp failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return bsl::SafeU16::failure();
        }

        if crate::BF_INVALID_ID == vpid {
            error!(
                "the vpid {:#06x} returned by bf_vp_op_create_vp is invalid\n{}",
                vpid,
                bsl::here()
            );

            return bsl::SafeU16::failure();
        }

        if crate::HYPERVISOR_MAX_VPS <= bsl::to_umx(vpid) {
            error!(
                "the vpid {:#06x} returned by bf_vp_op_create_vp is out of range\n{}",
                vpid,
                bsl::here()
            );

            return bsl::SafeU16::failure();
        }

        return vpid;
    }

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to destroy a VP
    ///     given an ID.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vpid The ID of the VP to destroy
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    pub fn bf_vp_op_destroy_vp(&self, vpid: bsl::SafeU16) -> bsl::ErrcType {
        let ret: u64;

        bsl::expects(vpid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vpid);
        bsl::expects(crate::HYPERVISOR_MAX_VPS > bsl::to_umx(vpid));

        unsafe {
            ret = crate::bf_vp_op_destroy_vp_impl(self.m_hndl.get(), vpid.get());
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_vp_op_destroy_vp failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return bsl::errc_failure;
        }

        return bsl::errc_success;
    }

    // ---------------------------------------------------------------------
    // bf_vs_ops
    // ---------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to create a VS
    ///     and return it's ID.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vpid The ID of the VP to assign the newly created VS to
    ///   @param ppid The resulting VSID of the newly created VS
    ///   @return Returns the resulting ID, or bsl::SafeU16::failure()
    ///     on failure.
    ///
    ///
    pub fn bf_vs_op_create_vs(&self, vpid: bsl::SafeU16, ppid: bsl::SafeU16) -> bsl::SafeU16 {
        let ret: u64;
        let mut vsid: bsl::SafeU16 = bsl::SafeU16::default();

        bsl::expects(vpid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vpid);
        bsl::expects(crate::HYPERVISOR_MAX_VPS > bsl::to_umx(vpid));
        bsl::expects(ppid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != ppid);
        bsl::expects(crate::HYPERVISOR_MAX_VPS > bsl::to_umx(ppid));

        unsafe {
            ret = crate::bf_vs_op_create_vs_impl(
                self.m_hndl.get(),
                vpid.get(),
                ppid.get(),
                vsid.data(),
            );
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_vs_op_create_vs failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return bsl::SafeU16::failure();
        }

        if crate::BF_INVALID_ID == vsid {
            error!(
                "the vsid {:#06x} returned by bf_vs_op_create_vs is invalid\n{}",
                vsid,
                bsl::here()
            );

            return bsl::SafeU16::failure();
        }

        if crate::HYPERVISOR_MAX_VSS <= bsl::to_umx(vsid) {
            error!(
                "the vsid {:#06x} returned by bf_vs_op_create_vs is out of range\n{}",
                vsid,
                bsl::here()
            );

            return bsl::SafeU16::failure();
        }

        return vsid;
    }

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to destroy a VS
    ///     given an ID.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vsid The ID of the VS to destroy
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    pub fn bf_vs_op_destroy_vs(&self, vsid: bsl::SafeU16) -> bsl::ErrcType {
        let ret: u64;

        bsl::expects(vsid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vsid);
        bsl::expects(crate::HYPERVISOR_MAX_VPS > bsl::to_umx(vsid));

        unsafe {
            ret = crate::bf_vs_op_destroy_vs_impl(self.m_hndl.get(), vsid.get());
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_vs_op_destroy_vs failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return bsl::errc_failure;
        }

        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to initialize a VS using
    ///     the root VP state provided by the loader using the current PPID.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vsid The ID of the VS to initialize
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    pub fn bf_vs_op_init_as_root(&self, vsid: bsl::SafeU16) -> bsl::ErrcType {
        let ret: u64;

        bsl::expects(vsid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vsid);
        bsl::expects(crate::HYPERVISOR_MAX_VPS > bsl::to_umx(vsid));

        unsafe {
            ret = crate::bf_vs_op_init_as_root_impl(self.m_hndl.get(), vsid.get());
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_vs_op_init_as_root failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return bsl::errc_failure;
        }

        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief Reads a CPU register from the VS given a bf_reg_t. Note
    ///     that the bf_reg_t is architecture specific.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vsid The ID of the VS to read from
    ///   @param reg A bf_reg_t defining which register to read
    ///   @return Returns the value read, or bsl::SafeU64::failure()
    ///     on failure.
    ///
    pub fn bf_vs_op_read(&self, vsid: bsl::SafeU16, reg: u64) -> bsl::SafeU64 {
        let ret: u64;
        let mut val: bsl::SafeU64 = bsl::SafeU64::default();

        bsl::expects(vsid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vsid);
        bsl::expects(crate::HYPERVISOR_MAX_VPS > bsl::to_umx(vsid));
        bsl::expects(crate::BF_REG_T_INVALID > reg);
        bsl::expects(crate::BF_REG_T_UNSUPPORTED != reg);

        unsafe {
            ret = crate::bf_vs_op_read_impl(self.m_hndl.get(), vsid.get(), reg, val.data());
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_vs_op_read failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return bsl::SafeU64::failure();
        }

        return val;
    }

    /// <!-- description -->
    ///   @brief Writes to a CPU register in the VS given a bf_reg_t and the
    ///     value to write. Note that the bf_reg_t is architecture specific.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vsid The ID of the VS to write to
    ///   @param reg A bf_reg_t defining which register to write to
    ///   @param value The value to write to the requested register
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    pub fn bf_vs_op_write(&self, vsid: bsl::SafeU16, reg: u64, val: bsl::SafeU64) -> bsl::ErrcType {
        let ret: u64;

        bsl::expects(vsid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vsid);
        bsl::expects(crate::HYPERVISOR_MAX_VPS > bsl::to_umx(vsid));
        bsl::expects(crate::BF_REG_T_INVALID > reg);
        bsl::expects(crate::BF_REG_T_UNSUPPORTED != reg);
        bsl::expects(val.is_valid_and_checked());

        unsafe {
            ret = crate::bf_vs_op_write_impl(self.m_hndl.get(), vsid.get(), reg, val.get());
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_vs_op_write failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return bsl::errc_failure;
        }

        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief Executes a VS given the ID of the VM, VP and VS to execute.
    ///     The VS must be assigned to the provided VP and the provided VP must
    ///     be assigned to the provided VM. The VP and VS must not be executing
    ///     on any other PP, and the VS must be assigned to the PP this syscall
    ///     is executed on. Upon success, this syscall will not return.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vmid The ID of the VM to run
    ///   @param vpid The ID of the VP to run
    ///   @param vsid The ID of the VS to run
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    pub fn bf_vs_op_run(
        &self,
        vmid: bsl::SafeU16,
        vpid: bsl::SafeU16,
        vsid: bsl::SafeU16,
    ) -> bsl::ErrcType {
        let ret: u64;

        bsl::expects(vmid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vmid);
        bsl::expects(crate::HYPERVISOR_MAX_VPS > bsl::to_umx(vmid));
        bsl::expects(vpid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vpid);
        bsl::expects(crate::HYPERVISOR_MAX_VPS > bsl::to_umx(vpid));
        bsl::expects(vsid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vsid);
        bsl::expects(crate::HYPERVISOR_MAX_VPS > bsl::to_umx(vsid));

        unsafe {
            ret = crate::bf_vs_op_run_impl(self.m_hndl.get(), vmid.get(), vpid.get(), vsid.get());
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_vs_op_run failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return bsl::errc_failure;
        }

        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief bf_vs_op_run_current tells the microkernel to execute the
    ///     currently active VS, VP and VM.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    pub fn bf_vs_op_run_current(&self) -> bsl::ErrcType {
        let ret: u64;

        unsafe {
            ret = crate::bf_vs_op_run_current_impl(self.m_hndl.get());
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_vs_op_run_current failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return bsl::errc_failure;
        }

        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief Advances the IP and executes a VS given the ID of the VM, VP
    ///     and VS to execute. The VS must be assigned to the provided VP and
    ///     the provided VP must be assigned to the provided VM. The VP and VS
    ///     must not be executing on any other PP, and the VS must be assigned
    ///     to the PP this syscall is executed on. Upon success, this syscall
    ///     will not return.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vmid The ID of the VM to advance the IP for
    ///   @param vpid The ID of the VP to advance the IP for
    ///   @param vsid The ID of the VS to advance the IP for
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    pub fn bf_vs_op_advance_ip_and_run(
        &self,
        vmid: bsl::SafeU16,
        vpid: bsl::SafeU16,
        vsid: bsl::SafeU16,
    ) -> bsl::ErrcType {
        let ret: u64;

        bsl::expects(vmid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vmid);
        bsl::expects(crate::HYPERVISOR_MAX_VPS > bsl::to_umx(vmid));
        bsl::expects(vpid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vpid);
        bsl::expects(crate::HYPERVISOR_MAX_VPS > bsl::to_umx(vpid));
        bsl::expects(vsid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vsid);
        bsl::expects(crate::HYPERVISOR_MAX_VPS > bsl::to_umx(vsid));

        unsafe {
            ret = crate::bf_vs_op_advance_ip_and_run_impl(
                self.m_hndl.get(),
                vmid.get(),
                vpid.get(),
                vsid.get(),
            );
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_vs_op_advance_ip_and_run failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return bsl::errc_failure;
        }

        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief bf_vs_op_advance_ip_and_run_current tells the microkernel to
    ///     advance the IP of and execute the currently active VS, VP and VM.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    pub fn bf_vs_op_advance_ip_and_run_current(&self) -> bsl::ErrcType {
        let ret: u64;

        unsafe {
            ret = crate::bf_vs_op_advance_ip_and_run_current_impl(self.m_hndl.get());
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_vs_op_advance_ip_and_run_current failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return bsl::errc_failure;
        }

        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to promote the requested
    ///     VS. This will stop the hypervisor complete on the physical
    ///     processor that this syscall is executed on and replace it's state
    ///     with the state in the VS. Note that this syscall only returns
    ///     on error.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vsid The ID of the VS to promote
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    pub fn bf_vs_op_promote(&self, vsid: bsl::SafeU16) -> bsl::ErrcType {
        let ret: u64;

        bsl::expects(vsid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vsid);
        bsl::expects(crate::HYPERVISOR_MAX_VPS > bsl::to_umx(vsid));

        unsafe {
            ret = crate::bf_vs_op_promote_impl(self.m_hndl.get(), vsid.get());
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_vs_op_promote failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return bsl::errc_failure;
        }

        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief bf_vs_op_clear tells the microkernel to clear the VS's
    ///     hardware cache, if one exists. How this is used depends entirely
    ///     on the hardware and is associated with AMD's VMCB Clean Bits,
    ///     and Intel's VMClear instruction. See the associated documentation
    ///     for more details. On AMD, this ABI clears the entire VMCB. For more
    ///     fine grained control, use the write ABIs to manually modify the
    ///     VMCB.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vsid The ID of the VS to clear
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    pub fn bf_vs_op_clear(&self, vsid: bsl::SafeU16) -> bsl::ErrcType {
        let ret: u64;

        bsl::expects(vsid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vsid);
        bsl::expects(crate::HYPERVISOR_MAX_VPS > bsl::to_umx(vsid));

        unsafe {
            ret = crate::bf_vs_op_clear_impl(self.m_hndl.get(), vsid.get());
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_vs_op_clear failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return bsl::errc_failure;
        }

        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief Migrates a VS to the provided PP. The VS must not be active.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vsid The ID of the VS to migrate
    ///   @param ppid The ID of the PP to migrate the VS to
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    pub fn bf_vs_op_migrate(&self, vsid: bsl::SafeU16, ppid: bsl::SafeU16) -> bsl::ErrcType {
        let ret: u64;

        bsl::expects(vsid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vsid);
        bsl::expects(crate::HYPERVISOR_MAX_VPS > bsl::to_umx(vsid));
        bsl::expects(ppid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != ppid);
        bsl::expects(crate::HYPERVISOR_MAX_VPS > bsl::to_umx(ppid));

        unsafe {
            ret = crate::bf_vs_op_migrate_impl(self.m_hndl.get(), vsid.get(), ppid.get());
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_vs_op_migrate failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return bsl::errc_failure;
        }

        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief TODO
    ///
    /// <!-- inputs/outputs -->
    ///   @param vmid The ID of the VM to run
    ///   @param vpid The ID of the VP to run
    ///   @param vsid The ID of the VS to run
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    pub fn bf_vs_op_set_active(
        &self,
        vmid: bsl::SafeU16,
        vpid: bsl::SafeU16,
        vsid: bsl::SafeU16,
    ) -> bsl::ErrcType {
        let ret: u64;

        bsl::expects(vmid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vmid);
        bsl::expects(crate::HYPERVISOR_MAX_VPS > bsl::to_umx(vmid));
        bsl::expects(vpid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vpid);
        bsl::expects(crate::HYPERVISOR_MAX_VPS > bsl::to_umx(vpid));
        bsl::expects(vsid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vsid);
        bsl::expects(crate::HYPERVISOR_MAX_VPS > bsl::to_umx(vsid));

        unsafe {
            ret = crate::bf_vs_op_set_active_impl(
                self.m_hndl.get(),
                vmid.get(),
                vpid.get(),
                vsid.get(),
            );
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_vs_op_set_active failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return bsl::errc_failure;
        }

        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief TODO
    ///
    /// <!-- inputs/outputs -->
    ///   @param vmid The ID of the VM to run
    ///   @param vpid The ID of the VP to run
    ///   @param vsid The ID of the VS to run
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    pub fn bf_vs_op_advance_ip_and_set_active(
        &self,
        vmid: bsl::SafeU16,
        vpid: bsl::SafeU16,
        vsid: bsl::SafeU16,
    ) -> bsl::ErrcType {
        let ret: u64;

        bsl::expects(vmid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vmid);
        bsl::expects(crate::HYPERVISOR_MAX_VPS > bsl::to_umx(vmid));
        bsl::expects(vpid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vpid);
        bsl::expects(crate::HYPERVISOR_MAX_VPS > bsl::to_umx(vpid));
        bsl::expects(vsid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vsid);
        bsl::expects(crate::HYPERVISOR_MAX_VPS > bsl::to_umx(vsid));

        unsafe {
            ret = crate::bf_vs_op_advance_ip_and_set_active_impl(
                self.m_hndl.get(),
                vmid.get(),
                vpid.get(),
                vsid.get(),
            );
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_vs_op_advance_ip_and_set_active failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return bsl::errc_failure;
        }

        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief Given the ID of a VS, invalidates a TLB entry for a given
    ///     GLA on the PP that this is executed on.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vsid The ID of the VS to invalidate
    ///   @param gla The GLA to invalidate
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    pub fn bf_vs_op_tlb_flush(&self, vsid: bsl::SafeU16, gla: bsl::SafeU64) -> bsl::ErrcType {
        let ret: u64;

        bsl::expects(vsid.is_valid_and_checked());
        bsl::expects(crate::BF_INVALID_ID != vsid);
        bsl::expects(crate::HYPERVISOR_MAX_VPS > bsl::to_umx(vsid));
        bsl::expects(gla.is_valid_and_checked());
        bsl::expects(gla.is_pos());
        bsl::expects(crate::bf_is_page_aligned(gla));

        unsafe {
            ret = crate::bf_vs_op_tlb_flush_impl(self.m_hndl.get(), vsid.get(), gla.get());
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_vs_op_tlb_flush failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return bsl::errc_failure;
        }

        return bsl::errc_success;
    }

    // ---------------------------------------------------------------------
    // bf_intrinsic_ops
    // ---------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Reads an MSR directly from the CPU given the address of
    ///     the MSR to read. Note that this is specific to Intel/AMD only.
    ///     Also note that not all MSRs can be read, and which MSRs that
    ///     can be read is up to the microkernel's internal policy as well
    ///     as which architecture the hypervisor is running on.
    ///
    /// <!-- inputs/outputs -->
    ///   @param msr The address of the MSR to read
    ///   @return Returns the value read, or bsl::SafeU64::failure()
    ///     on failure.
    ///
    pub fn bf_intrinsic_op_rdmsr(&self, msr: bsl::SafeU32) -> bsl::SafeU64 {
        let ret: u64;
        let mut val: bsl::SafeU64 = bsl::SafeU64::default();

        bsl::expects(msr.is_valid_and_checked());
        bsl::expects(msr.is_pos());

        unsafe {
            ret = crate::bf_intrinsic_op_rdmsr_impl(self.m_hndl.get(), msr.get(), val.data());
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_intrinsic_op_rdmsr failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return bsl::SafeU64::failure();
        }

        return val;
    }

    /// <!-- description -->
    ///   @brief Writes to an MSR directly from the CPU given the address of
    ///     the MSR to write as well as the value to write. Note that this is
    ///     specific to Intel/AMD only. Also note that not all MSRs can be
    ///     written to, and which MSRs that can be written to is up to the
    ///     microkernel's internal policy as well as which architecture the
    ///     hypervisor is running on.
    ///
    /// <!-- inputs/outputs -->
    ///   @param msr The address of the MSR to write to
    ///   @param val The value to write to the requested MSR
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    pub fn bf_intrinsic_op_wrmsr(&self, msr: bsl::SafeU32, val: bsl::SafeU64) -> bsl::ErrcType {
        let ret: u64;

        bsl::expects(msr.is_valid_and_checked());
        bsl::expects(msr.is_pos());
        bsl::expects(val.is_valid_and_checked());

        unsafe {
            ret = crate::bf_intrinsic_op_wrmsr_impl(self.m_hndl.get(), msr.get(), val.get());
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_intrinsic_op_wrmsr failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return bsl::errc_failure;
        }

        return bsl::errc_success;
    }

    // ---------------------------------------------------------------------
    // bf_mem_ops
    // ---------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief bf_mem_op_alloc_page allocates a page, and maps this page
    ///     into the direct map of the VM.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of pointer to return. Must be a POD type and
    ///     the size of a page.
    ///   @param mut_phys The physical address of the resulting page
    ///   @return Returns a pointer to the newly allocated memory on success,
    ///     or a nullptr on failure.
    ///
    pub fn bf_mem_op_alloc_page<T>(&self, phys: &mut bsl::SafeU64) -> *mut T {
        let ret: u64;
        let mut ptr: bsl::CPtrT = core::ptr::null_mut();

        bsl::expects(phys.is_valid_and_checked());

        unsafe {
            ret = crate::bf_mem_op_alloc_page_impl(self.m_hndl.get(), &mut ptr, phys.data());
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_mem_op_alloc_page failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return core::ptr::null_mut();
        }

        return ptr as *mut T;
    }

    /// <!-- description -->
    ///   @brief bf_mem_op_alloc_huge allocates a physically contiguous block
    ///     of memory. When allocating a page, the extension should keep in
    ///     mind the following:
    ///       - The total memory available to allocate from this pool is
    ///         extremely limited. This should only be used when absolutely
    ///         needed, and extensions should not expect more than 1 MB (might
    ///         be less) of total memory available.
    ///       - Memory allocated from the huge pool might be allocated using
    ///         different schemes. For example, the microkernel might allocate
    ///         in increments of a page, or it might use a buddy allocator that
    ///         would allocate in multiples of 2. If the allocation size
    ///         doesn't match the algorithm, internal fragmentation could
    ///         occur, further limiting the total number of allocations this
    ///         pool can support.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of pointer to return. Must be a POD type and
    ///     the size of a page.
    ///   @param size The total number of bytes to allocate
    ///   @param mut_phys The physical address of the resulting memory
    ///   @return Returns a pointer to the newly allocated memory on success,
    ///     or a nullptr on failure.
    ///
    pub fn bf_mem_op_alloc_huge<T>(&self, size: bsl::SafeU64, phys: &mut bsl::SafeU64) -> *mut T {
        let ret: u64;
        let mut ptr: bsl::CPtrT = core::ptr::null_mut();

        bsl::expects(size.is_valid_and_checked());
        bsl::expects(size.is_pos());
        bsl::expects(crate::bf_is_page_aligned(size));
        bsl::expects(phys.is_valid_and_checked());

        unsafe {
            ret = crate::bf_mem_op_alloc_huge_impl(
                self.m_hndl.get(),
                size.get(),
                &mut ptr,
                phys.data(),
            );
        }
        if crate::BF_STATUS_SUCCESS != ret {
            error!(
                "bf_mem_op_alloc_huge failed with status {:#018x}\n{}",
                ret,
                bsl::here()
            );

            return core::ptr::null_mut();
        }

        return ptr as *mut T;
    }
}
