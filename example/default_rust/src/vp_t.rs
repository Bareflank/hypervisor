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
pub struct VpT {
    /// @brief stores the ID associated with this dVpT
    m_id: bsl::SafeU16,
    /// @brief stores whether or not this dVpT is allocated.
    m_allocated: crate::AllocatedStatusT,
    /// @brief stores the ID of the VM this dVpT is assigned to
    m_assigned_vmid: bsl::SafeU16,
}

impl VpT {
    /// <!-- description -->
    ///   @brief creates a new VpT
    ///
    pub const fn new() -> Self {
        Self {
            m_id: bsl::SafeU16::new(0),
            m_allocated: crate::AllocatedStatusT::Deallocated,
            m_assigned_vmid: bsl::SafeU16::new(0),
        }
    }

    /// <!-- description -->
    ///   @brief Initializes this dVpT
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param tls the tls_t to use
    ///   @param sys the bf_syscall_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param i the ID for this dVpT
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
    ///   @brief Release the dVpT.
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
    ///   @brief Returns the ID of this dVpT
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the ID of this dVpT
    ///
    pub fn id(&self) -> bsl::SafeU16 {
        bsl::ensures(self.m_id.is_valid_and_checked());
        return !self.m_id;
    }

    /// <!-- description -->
    ///   @brief Allocates the dVpT and returns it's ID
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param tls the tls_t to use
    ///   @param sys the bf_syscall_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param vmid the ID of the VM to assign the dVpT to
    ///   @return Returns ID of this dVpT
    ///
    pub fn allocate(
        &mut self,
        gs: &crate::GsT,
        tls: &crate::TlsT,
        sys: &syscall::BfSyscallT,
        intrinsic: &crate::IntrinsicT,
        vmid: bsl::SafeU16,
    ) -> bsl::SafeU16 {
        bsl::expects(self.id() != syscall::BF_INVALID_ID);
        bsl::expects(crate::AllocatedStatusT::Deallocated == self.m_allocated);

        bsl::expects(vmid.is_valid_and_checked());
        bsl::expects(vmid != syscall::BF_INVALID_ID);

        bsl::discard(gs);
        bsl::discard(tls);
        bsl::discard(sys);
        bsl::discard(intrinsic);

        self.m_assigned_vmid = !vmid;
        self.m_allocated = crate::AllocatedStatusT::Allocated;

        return self.id();
    }

    /// <!-- description -->
    ///   @brief Deallocates the dVpT
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

        self.m_assigned_vmid = bsl::SafeU16::default();
        self.m_allocated = crate::AllocatedStatusT::Deallocated;
    }

    /// <!-- description -->
    ///   @brief Returns true if this dVpT is allocated, false otherwise
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if this dVpT is allocated, false otherwise
    ///
    pub fn is_allocated(&self) -> bool {
        return self.m_allocated == crate::AllocatedStatusT::Allocated;
    }

    /// <!-- description -->
    ///   @brief Returns true if this dVpT is deallocated, false otherwise
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if this dVpT is deallocated, false otherwise
    ///
    pub fn is_deallocated(&self) -> bool {
        return self.m_allocated == crate::AllocatedStatusT::Deallocated;
    }

    /// <!-- description -->
    ///   @brief Returns the ID of the VM this dVpT is assigned to. If
    ///     this dVpT is not assigned, syscall::BF_INVALID_ID is returned.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the ID of the VM this dVpT is assigned to. If
    ///     this dVpT is not assigned, syscall::BF_INVALID_ID is returned.
    ///
    pub fn assigned_vm(&self) -> bsl::SafeU16 {
        bsl::ensures(self.m_assigned_vmid.is_valid_and_checked());
        return !self.m_assigned_vmid;
    }
}
