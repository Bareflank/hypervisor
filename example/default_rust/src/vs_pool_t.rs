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

pub struct VsPoolT {
    m_pool: [crate::VsT; *syscall::HYPERVISOR_MAX_VSS.get_unsafe()],
}

impl VsPoolT {
    /// <!-- description -->
    ///   @brief Returns the VsT associated with the provided vsid.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vsid the ID of the VsT to get
    ///   @return Returns the VsT associated with the provided vsid.
    ///
    fn get_vs(&mut self, vsid: bsl::SafeU16) -> &mut crate::VsT {
        bsl::expects(vsid.is_valid_and_checked());
        bsl::expects(vsid < bsl::to_u16(self.m_pool.len()));
        return &mut self.m_pool[bsl::to_umx(vsid).get()];
    }

    /// <!-- description -->
    ///   @brief Returns the VsT associated with the provided vsid.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vsid the ID of the VsT to get
    ///   @return Returns the VsT associated with the provided vsid.
    ///
    fn get_vs_const(&self, vsid: bsl::SafeU16) -> &crate::VsT {
        bsl::expects(vsid.is_valid_and_checked());
        bsl::expects(vsid < bsl::to_u16(self.m_pool.len()));
        return &self.m_pool[bsl::to_umx(vsid).get()];
    }

    /// <!-- description -->
    ///   @brief creates a new VsPoolT
    ///
    pub const fn new() -> Self {
        Self {
            m_pool: [crate::VsT::new(); *syscall::HYPERVISOR_MAX_VSS.get_unsafe()],
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
    ///   @param vpid the ID of the VP to assign the newly created VP to
    ///   @param ppid the ID of the PP to assign the newly created VP to
    ///   @return Returns ID of the newly allocated VsT. Returns
    ///     bsl::SafeU16::failure() on failure.
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
        // NOTE:
        // - Ask the microkernel to create a VP and return the ID of the
        //   newly created VP.
        //

        let vsid = sys.bf_vs_op_create_vs(vpid, ppid);
        if vsid.is_invalid() {
            print_v!("{}", bsl::here());
            return bsl::SafeU16::failure();
        }

        // NOTE:
        // - Once a VP has been created, the microkernel returns the ID
        //   of the newly created VP. We can use this ID to determine
        //   which VsT to allocate.
        //

        return self
            .get_vs(vsid)
            .allocate(gs, tls, sys, intrinsic, vpid, ppid);
    }

    /// <!-- description -->
    ///   @brief Deallocates the requested VsT
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param tls the tls_t to use
    ///   @param sys the bf_syscall_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param vsid the ID of the VsT to deallocate
    ///
    pub fn deallocate(
        &mut self,
        gs: &crate::GsT,
        tls: &crate::TlsT,
        sys: &mut syscall::BfSyscallT,
        intrinsic: &crate::IntrinsicT,
        vsid: bsl::SafeU16,
    ) {
        let vs = self.get_vs(vsid);

        // NOTE:
        // - If the requested VP was allocated, we need to tell the
        //   microkernel to destroy it. Once that is done we can
        //   deallocate the VsT so that it can be used again in the
        //   future.
        //

        if vs.is_allocated() {
            bsl::expects(sys.bf_vs_op_destroy_vs(vsid));
            vs.deallocate(gs, tls, sys, intrinsic);
        } else {
            bsl::touch();
        }
    }

    /// <!-- description -->
    ///   @brief Returns true if the requested VsT is allocated,
    ///     false otherwise
    ///
    /// <!-- inputs/outputs -->
    ///   @param vpid the ID of the VsT to query
    ///   @return Returns true if the requested VsT is allocated,
    ///     false otherwise
    ///
    pub fn is_allocated(&self, vpid: bsl::SafeU16) -> bool {
        return self.get_vs_const(vpid).is_allocated();
    }

    /// <!-- description -->
    ///   @brief Returns true if the requested VsT is deallocated,
    ///     false otherwise
    ///
    /// <!-- inputs/outputs -->
    ///   @param vpid the ID of the VsT to query
    ///   @return Returns true if the requested VsT is deallocated,
    ///     false otherwise
    ///
    pub fn is_deallocated(&self, vpid: bsl::SafeU16) -> bool {
        return self.get_vs_const(vpid).is_deallocated();
    }

    /// <!-- description -->
    ///   @brief Returns the ID of the VP the requested VsT is assigned
    ///     to. If the VsT is not assigned, syscall::BF_INVALID_ID is
    ///     returned.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vpid the ID of the VsT to query
    ///   @return Returns the ID of the VP the requested VsT is assigned
    ///     to. If the VsT is not assigned, syscall::BF_INVALID_ID is
    ///     returned.
    ///
    pub fn assigned_vp(&self, vpid: bsl::SafeU16) -> bsl::SafeU16 {
        return self.get_vs_const(vpid).assigned_vp();
    }

    /// <!-- description -->
    ///   @brief Returns the ID of the PP the requested VsT is assigned
    ///     to. If the VsT is not assigned, syscall::BF_INVALID_ID is
    ///     returned.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vpid the ID of the VsT to query
    ///   @return Returns the ID of the PP the requested VsT is assigned
    ///     to. If the VsT is not assigned, syscall::BF_INVALID_ID is
    ///     returned.
    ///
    pub fn assigned_pp(&self, vpid: bsl::SafeU16) -> bsl::SafeU16 {
        return self.get_vs_const(vpid).assigned_pp();
    }
}
