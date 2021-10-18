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

#[derive(Debug, Copy, Clone)]
pub struct VsT {
    /// @brief stores the ID associated with this VsT
    m_id: bsl::SafeU16,
    /// @brief stores whether or not this VsT is allocated.
    m_allocated: crate::AllocatedStatusT,
    /// @brief stores the ID of the VP this VsT is assigned to
    m_assigned_vpid: bsl::SafeU16,
    /// @brief stores the ID of the PP this VsT is assigned to
    m_assigned_ppid: bsl::SafeU16,
}

impl VsT {
    /// <!-- description -->
    ///   @brief creates a new VsT
    ///
    pub const fn new() -> Self {
        Self {
            m_id: bsl::SafeU16::new(0),
            m_allocated: crate::AllocatedStatusT::Deallocated,
            m_assigned_vpid: bsl::SafeU16::new(0),
            m_assigned_ppid: bsl::SafeU16::new(0),
        }
    }

    /// <!-- description -->
    ///   @brief Initializes this VsT
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param tls the tls_t to use
    ///   @param sys the bf_syscall_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param i the ID for this VsT
    ///
    pub fn initialize(
        &mut self,
        gs: &crate::GsT,
        tls: &crate::TlsT,
        sys: &syscall::BfSyscallT,
        intrinsic: &crate::IntrinsicT,
        i: bsl::SafeU16,
    ) {
        bsl::expects(self.id() == syscall::BF_INVALID_ID);
        bsl::expects(self.m_allocated == crate::AllocatedStatusT::Deallocated);

        bsl::expects(i.is_valid_and_checked());
        bsl::expects(i != syscall::BF_INVALID_ID);

        bsl::discard(gs);
        bsl::discard(tls);
        bsl::discard(sys);
        bsl::discard(intrinsic);

        self.m_id = !i;
    }

    /// <!-- description -->
    ///   @brief Release the VsT.
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param tls the tls_t to use
    ///   @param sys the bf_syscall_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///
    pub fn release(
        &mut self,
        gs: &crate::GsT,
        tls: &crate::TlsT,
        sys: &syscall::BfSyscallT,
        intrinsic: &crate::IntrinsicT,
    ) {
        self.deallocate(gs, tls, sys, intrinsic);
        self.m_id = bsl::SafeU16::default();
    }

    /// <!-- description -->
    ///   @brief Returns the ID of this VsT
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the ID of this VsT
    ///
    pub fn id(&self) -> bsl::SafeU16 {
        bsl::ensures(self.m_id.is_valid_and_checked());
        return !self.m_id;
    }

    /// <!-- description -->
    ///   @brief Allocates the VsT and returns it's ID
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param tls the tls_t to use
    ///   @param sys the bf_syscall_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param vpid the ID of the VP to assign the VsT to
    ///   @param ppid the ID of the PP to assign the VsT to
    ///   @return Returns ID of this VsT
    ///
    pub fn allocate(
        &mut self,
        gs: &crate::GsT,
        tls: &crate::TlsT,
        sys: &mut syscall::BfSyscallT,
        intrinsic: &crate::IntrinsicT,
        vpid: bsl::SafeU16,
        ppid: bsl::SafeU16,
    ) -> bsl::SafeU16 {
        bsl::expects(self.id() != syscall::BF_INVALID_ID);
        bsl::expects(crate::AllocatedStatusT::Deallocated == self.m_allocated);

        bsl::expects(vpid.is_valid_and_checked());
        bsl::expects(vpid != syscall::BF_INVALID_ID);
        bsl::expects(ppid.is_valid_and_checked());
        bsl::expects(ppid != syscall::BF_INVALID_ID);

        bsl::discard(gs);
        bsl::discard(tls);
        bsl::discard(intrinsic);

        let vmcs_vpid_val = bsl::SafeU64::new(0x1);
        let vmcs_vpid_idx = syscall::BF_REG_T_VIRTUAL_PROCESSOR_IDENTIFIER;
        bsl::expects(sys.bf_vs_op_write(self.id(), vmcs_vpid_idx, vmcs_vpid_val));

        let vmcs_link_ptr_val = bsl::SafeU64::new(0xFFFFFFFFFFFFFFFF);
        let vmcs_link_ptr_idx = syscall::BF_REG_T_VMCS_LINK_POINTER;
        bsl::expects(sys.bf_vs_op_write(self.id(), vmcs_link_ptr_idx, vmcs_link_ptr_val));

        let pin_ctls = bsl::SafeU64::default();
        let mut proc_ctls = bsl::SafeU64::default();
        let exit_ctls = bsl::SafeU64::default();
        let mut entry_ctls = bsl::SafeU64::default();
        let mut proc2_ctls = bsl::SafeU64::default();

        let enable_msr_bitmaps = bsl::SafeU64::new(0x10000000);
        let enable_proc2_ctls = bsl::SafeU64::new(0x80000000);

        proc_ctls |= enable_msr_bitmaps;
        proc_ctls |= enable_proc2_ctls;

        let enable_ia32e_mode = bsl::SafeU64::new(0x00000200);

        entry_ctls |= enable_ia32e_mode;

        let enable_vpid = bsl::SafeU64::new(0x00000020);
        let enable_rdtscp = bsl::SafeU64::new(0x00000008);
        let enable_invpcid = bsl::SafeU64::new(0x00001000);
        let enable_xsave = bsl::SafeU64::new(0x00100000);
        let enable_uwait = bsl::SafeU64::new(0x04000000);

        proc2_ctls |= enable_vpid;
        proc2_ctls |= enable_rdtscp;
        proc2_ctls |= enable_invpcid;
        proc2_ctls |= enable_xsave;
        proc2_ctls |= enable_uwait;

        let idx = syscall::BF_REG_T_PIN_BASED_VM_EXECUTION_CTLS;
        bsl::expects(sys.bf_vs_op_write(self.id(), idx, pin_ctls));

        let idx = syscall::BF_REG_T_PRIMARY_PROC_BASED_VM_EXECUTION_CTLS;
        bsl::expects(sys.bf_vs_op_write(self.id(), idx, proc_ctls));

        let idx = syscall::BF_REG_T_VMEXIT_CTLS;
        bsl::expects(sys.bf_vs_op_write(self.id(), idx, exit_ctls));

        let idx = syscall::BF_REG_T_VMENTRY_CTLS;
        bsl::expects(sys.bf_vs_op_write(self.id(), idx, entry_ctls));

        let idx = syscall::BF_REG_T_SECONDARY_PROC_BASED_VM_EXECUTION_CTLS;
        bsl::expects(sys.bf_vs_op_write(self.id(), idx, proc2_ctls));

        let idx = syscall::BF_REG_T_ADDRESS_OF_MSR_BITMAPS;
        bsl::expects(sys.bf_vs_op_write(self.id(), idx, gs.msr_bitmap_phys));

        if syscall::BfSyscallT::is_vs_a_root_vs(self.id()) {
            bsl::expects(sys.bf_vs_op_init_as_root(self.id()));
        } else {
            bsl::touch();
        }

        self.m_assigned_vpid = !vpid;
        self.m_assigned_ppid = !ppid;
        self.m_allocated = crate::AllocatedStatusT::Allocated;

        return self.id();
    }

    /// <!-- description -->
    ///   @brief Deallocates the VsT
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param tls the tls_t to use
    ///   @param sys the bf_syscall_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///
    pub fn deallocate(
        &mut self,
        gs: &crate::GsT,
        tls: &crate::TlsT,
        sys: &syscall::BfSyscallT,
        intrinsic: &crate::IntrinsicT,
    ) {
        bsl::discard(gs);
        bsl::discard(tls);
        bsl::discard(sys);
        bsl::discard(intrinsic);

        self.m_assigned_ppid = bsl::SafeU16::default();
        self.m_assigned_vpid = bsl::SafeU16::default();
        self.m_allocated = crate::AllocatedStatusT::Deallocated;
    }

    /// <!-- description -->
    ///   @brief Returns true if this VsT is allocated, false otherwise
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if this VsT is allocated, false otherwise
    ///
    pub fn is_allocated(&self) -> bool {
        return self.m_allocated == crate::AllocatedStatusT::Allocated;
    }

    /// <!-- description -->
    ///   @brief Returns true if this VsT is deallocated, false otherwise
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if this VsT is deallocated, false otherwise
    ///
    pub fn is_deallocated(&self) -> bool {
        return self.m_allocated == crate::AllocatedStatusT::Deallocated;
    }

    /// <!-- description -->
    ///   @brief Returns the ID of the VP this VsT is assigned to. If
    ///     this VsT is not assigned, syscall::BF_INVALID_ID is returned.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the ID of the VP this VsT is assigned to. If
    ///     this VsT is not assigned, syscall::BF_INVALID_ID is returned.
    ///
    pub fn assigned_vp(&self) -> bsl::SafeU16 {
        bsl::ensures(self.m_assigned_vpid.is_valid_and_checked());
        return !self.m_assigned_vpid;
    }

    /// <!-- description -->
    ///   @brief Returns the ID of the PP this VsT is assigned to. If
    ///     this VsT is not assigned, syscall::BF_INVALID_ID is returned.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the ID of the PP this VsT is assigned to. If
    ///     this VsT is not assigned, syscall::BF_INVALID_ID is returned.
    ///
    pub fn assigned_pp(&self) -> bsl::SafeU16 {
        bsl::ensures(self.m_assigned_ppid.is_valid_and_checked());
        return !self.m_assigned_ppid;
    }
}
