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

#ifndef VS_STATE_SAVE_T_HPP
#define VS_STATE_SAVE_T_HPP

#include <bsl/cstdint.hpp>

#pragma pack(push, 1)

namespace mk
{
    /// @struct mk::vmcs_missing_registers_t
    ///
    /// <!-- description -->
    ///   @brief Stores the state for the VS that the VMCB/VMCS cannot like
    ///     the general purpose registers, debug registers, control registers,
    ///     some MSRs, etc...
    ///
    struct vmcs_missing_registers_t final
    {
        /// @brief stores the value of cr2 (0x000)
        bsl::uintmx guest_cr2;
        /// @brief stores the value of dr6 (0x008)
        bsl::uintmx guest_dr6;

        /// @brief stores the guest value of star (0x010)
        bsl::uintmx guest_star;
        /// @brief stores the guest value of lstar (0x018)
        bsl::uintmx guest_lstar;
        /// @brief stores the guest value of cstar (0x020)
        bsl::uintmx guest_cstar;
        /// @brief stores the guest value of fmask (0x028)
        bsl::uintmx guest_fmask;
        /// @brief stores the guest value of kernel_gs_base (0x030)
        bsl::uintmx guest_kernel_gs_base;

        /// @brief stores the host value of star (0x038)
        bsl::uintmx host_star;
        /// @brief stores the host value of lstar (0x040)
        bsl::uintmx host_lstar;
        /// @brief stores the host value of cstar (0x048)
        bsl::uintmx host_cstar;
        /// @brief stores the host value of fmask (0x050)
        bsl::uintmx host_fmask;
        /// @brief stores the host value of kernel_gs_base (0x058)
        bsl::uintmx host_kernel_gs_base;

        /// @brief stores the launch status of the hypervisor (0x060)
        bsl::uintmx launched;
    };
}

#pragma pack(pop)

#endif
