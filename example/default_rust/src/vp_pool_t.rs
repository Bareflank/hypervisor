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

pub struct VpPoolT {
    m_pool: [crate::VpT; *syscall::HYPERVISOR_MAX_VPS.get_unsafe()],
}

impl VpPoolT {
    /// <!-- description -->
    ///   @brief Returns the VpT associated with the provided vpid.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vpid the ID of the VpT to get
    ///   @return Returns the VpT associated with the provided vpid.
    ///
    fn get_vp(&mut self, vpid: bsl::SafeU16) -> &mut crate::VpT {
        bsl::expects(vpid.is_valid_and_checked());
        bsl::expects(vpid < bsl::to_u16(self.m_pool.len()));
        return &mut self.m_pool[bsl::to_umx(vpid).get()];
    }

    /// <!-- description -->
    ///   @brief Returns the VpT associated with the provided vpid.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vpid the ID of the VpT to get
    ///   @return Returns the VpT associated with the provided vpid.
    ///
    fn get_vp_const(&self, vpid: bsl::SafeU16) -> &crate::VpT {
        bsl::expects(vpid.is_valid_and_checked());
        bsl::expects(vpid < bsl::to_u16(self.m_pool.len()));
        return &self.m_pool[bsl::to_umx(vpid).get()];
    }

    /// <!-- description -->
    ///   @brief creates a new VpPoolT
    ///
    pub const fn new() -> Self {
        Self {
            m_pool: [crate::VpT::new(); *syscall::HYPERVISOR_MAX_VPS.get_unsafe()],
        }
    }

    /// <!-- description -->
    ///   @brief Initializes this vp_pool_t
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param tls the tls_t to use
    ///   @param sys the bf_syscall_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///
    pub fn initialize(
        &mut self,
        gs: &crate::GsT,
        tls: &crate::TlsT,
        sys: &syscall::BfSyscallT,
        intrinsic: &crate::IntrinsicT,
    ) {
        for i in 0..self.m_pool.len() {
            self.m_pool[i].initialize(gs, tls, sys, intrinsic, bsl::to_u16(i));
        }
    }

    /// <!-- description -->
    ///   @brief Release the vp_pool_t.
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
        for i in 0..self.m_pool.len() {
            self.m_pool[i].release(gs, tls, sys, intrinsic);
        }
    }

    /// <!-- description -->
    ///   @brief Allocates a VP and returns it's ID
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param tls the tls_t to use
    ///   @param sys the bf_syscall_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param vmid the ID of the VM to assign the newly created VP to
    ///   @return Returns ID of the newly allocated VpT. Returns
    ///     bsl::SafeU16::failure() on failure.
    ///
    pub fn allocate(
        &mut self,
        gs: &crate::GsT,
        tls: &crate::TlsT,
        sys: &mut syscall::BfSyscallT,
        intrinsic: &crate::IntrinsicT,
        vmid: bsl::SafeU16,
    ) -> bsl::SafeU16 {
        // NOTE:
        // - Ask the microkernel to create a VP and return the ID of the
        //   newly created VP.
        //

        let vpid = sys.bf_vp_op_create_vp(vmid);
        if vpid.is_invalid() {
            print_v!("{}", bsl::here());
            return bsl::SafeU16::failure();
        }

        // NOTE:
        // - Once a VP has been created, the microkernel returns the ID
        //   of the newly created VP. We can use this ID to determine
        //   which VpT to allocate.
        //

        return self.get_vp(vpid).allocate(gs, tls, sys, intrinsic, vmid);
    }

    /// <!-- description -->
    ///   @brief Deallocates the requested VpT
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param tls the tls_t to use
    ///   @param sys the bf_syscall_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param vpid the ID of the VpT to deallocate
    ///
    pub fn deallocate(
        &mut self,
        gs: &crate::GsT,
        tls: &crate::TlsT,
        sys: &mut syscall::BfSyscallT,
        intrinsic: &crate::IntrinsicT,
        vpid: bsl::SafeU16,
    ) {
        let vp = self.get_vp(vpid);

        // NOTE:
        // - If the requested VP was allocated, we need to tell the
        //   microkernel to destroy it. Once that is done we can
        //   deallocate the VpT so that it can be used again in the
        //   future.
        //

        if vp.is_allocated() {
            bsl::expects(sys.bf_vp_op_destroy_vp(vpid));
            vp.deallocate(gs, tls, sys, intrinsic);
        } else {
            bsl::touch();
        }
    }

    /// <!-- description -->
    ///   @brief Returns true if the requested VpT is allocated,
    ///     false otherwise
    ///
    /// <!-- inputs/outputs -->
    ///   @param vpid the ID of the VpT to query
    ///   @return Returns true if the requested VpT is allocated,
    ///     false otherwise
    ///
    pub fn is_allocated(&self, vpid: bsl::SafeU16) -> bool {
        return self.get_vp_const(vpid).is_allocated();
    }

    /// <!-- description -->
    ///   @brief Returns true if the requested VpT is deallocated,
    ///     false otherwise
    ///
    /// <!-- inputs/outputs -->
    ///   @param vpid the ID of the VpT to query
    ///   @return Returns true if the requested VpT is deallocated,
    ///     false otherwise
    ///
    pub fn is_deallocated(&self, vpid: bsl::SafeU16) -> bool {
        return self.get_vp_const(vpid).is_deallocated();
    }

    /// <!-- description -->
    ///   @brief Returns the ID of the VM the requested VpT is assigned
    ///     to. If the VpT is not assigned, syscall::BF_INVALID_ID is
    ///     returned.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vpid the ID of the VpT to query
    ///   @return Returns the ID of the VM the requested VpT is assigned
    ///     to. If the VpT is not assigned, syscall::BF_INVALID_ID is
    ///     returned.
    ///
    pub fn assigned_vm(&self, vpid: bsl::SafeU16) -> bsl::SafeU16 {
        return self.get_vp_const(vpid).assigned_vm();
    }
}
