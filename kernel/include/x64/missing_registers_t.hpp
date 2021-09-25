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

#ifndef MISSING_REGISTERS_T_HPP
#define MISSING_REGISTERS_T_HPP

#include <bsl/cstdint.hpp>

#pragma pack(push, 1)

namespace mk
{
    /// @struct mk::missing_registers_t
    ///
    /// <!-- description -->
    ///   @brief Stores the state for the VS that the VMCB/VMCS cannot like
    ///     the general purpose registers, debug registers, control registers,
    ///     some MSRs, etc...
    ///
    struct missing_registers_t final
    {
        /// @brief stores the launch status of the hypervisor (0x000)
        bsl::uintmx launched;

        /// @brief stores the value of cr2 (0x008)
        bsl::uintmx guest_cr2;
        /// @brief stores the value of cr8 (0x010)
        bsl::uintmx guest_cr8;
        /// @brief stores the value of dr0 (0x018)
        bsl::uintmx guest_dr0;
        /// @brief stores the value of dr1 (0x020)
        bsl::uintmx guest_dr1;
        /// @brief stores the value of dr2 (0x028)
        bsl::uintmx guest_dr2;
        /// @brief stores the value of dr3 (0x030)
        bsl::uintmx guest_dr3;
        /// @brief stores the value of dr6 (0x038)
        bsl::uintmx guest_dr6;
        /// @brief reserved (0x040)
        bsl::uintmx reserved1;
        /// @brief reserved (0x048)
        bsl::uintmx reserved2;
        /// @brief reserved (0x050)
        bsl::uintmx reserved3;
        /// @brief reserved (0x058)
        bsl::uintmx reserved4;

        /// @brief stores the guest value of star (0x060)
        bsl::uintmx guest_star;
        /// @brief stores the guest value of lstar (0x068)
        bsl::uintmx guest_lstar;
        /// @brief stores the guest value of cstar (0x070)
        bsl::uintmx guest_cstar;
        /// @brief stores the guest value of fmask (0x078)
        bsl::uintmx guest_fmask;
        /// @brief stores the guest value of kernel_gs_base (0x080)
        bsl::uintmx guest_kernel_gs_base;
        /// @brief stores the value of xcr0 (0x088)
        bsl::uintmx guest_xcr0;
        /// @brief reserved for xss in the future (0x090)
        bsl::uintmx reserved_guest_xss;
        /// @brief reserved (0x098)
        bsl::uintmx reserved_guest1;
        /// @brief reserved (0x0A0)
        bsl::uintmx reserved_guest2;
        /// @brief reserved (0x0A8)
        bsl::uintmx reserved_guest3;

        /// @brief stores the host value of star (0x0B0)
        bsl::uintmx host_star;
        /// @brief stores the host value of lstar (0x0B8)
        bsl::uintmx host_lstar;
        /// @brief stores the host value of cstar (0x0C0)
        bsl::uintmx host_cstar;
        /// @brief stores the host value of fmask (0x0C8)
        bsl::uintmx host_fmask;
        /// @brief stores the host value of kernel_gs_base (0x0D0)
        bsl::uintmx host_kernel_gs_base;
        /// @brief stores the value of xcr0 (0x0D8)
        bsl::uintmx host_xcr0;
        /// @brief reserved for xss in the future (0x0E0)
        bsl::uintmx reserved_host_xss;
        /// @brief reserved (0x0E8)
        bsl::uintmx reserved_host1;
        /// @brief reserved (0x0F0)
        bsl::uintmx reserved_host2;
        /// @brief reserved (0x0F8)
        bsl::uintmx reserved_host3;
    };
}

#pragma pack(pop)

#endif
