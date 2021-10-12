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

#ifndef MOCKS_INTRINSIC_VMRUN_HPP
#define MOCKS_INTRINSIC_VMRUN_HPP

#include <bsl/cstdint.hpp>
#include <bsl/discard.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Executes the VMRun instruction. When this function returns
    ///     a "VMExit" has occurred and must be handled.
    ///
    /// <!-- inputs/outputs -->
    ///   @param pmut_guest_vmcb a pointer to the guest VMCB
    ///   @param guest_vmcb_phys the physical address of the guest VMCB
    ///   @param pmut_host_vmcb a pointer to the host VMCB
    ///   @param host_vmcb_phys the physical address of the host VMCB
    ///   @param pmut_missing_registers a pointer to the missing registers
    ///   @return Returns the exit reason associated with the VMExit
    ///
    [[nodiscard]] constexpr auto
    intrinsic_vmrun(
        void *const pmut_guest_vmcb,
        bsl::uintmx const guest_vmcb_phys,
        void *const pmut_host_vmcb,
        bsl::uintmx const host_vmcb_phys,
        void *const pmut_missing_registers) noexcept -> bsl::uintmx
    {
        bsl::discard(pmut_guest_vmcb);
        bsl::discard(guest_vmcb_phys);
        bsl::discard(pmut_host_vmcb);
        bsl::discard(host_vmcb_phys);
        bsl::discard(pmut_missing_registers);

        return {};
    }
}

#endif
