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

#ifndef MOCK_INTRINSIC_IMPL_PROTOTYPES_HPP
#define MOCK_INTRINSIC_IMPL_PROTOTYPES_HPP

#include <gs_t.hpp>

#include <bsl/cstdint.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace example
{
    /// <!-- description -->
    ///   @brief Executes the CPUID instruction given the provided EAX and ECX
    ///     and returns the results
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs a pointer to the global storage to use
    ///   @param pmut_rax the index used by CPUID, returns resulting rax
    ///   @param pmut_rbx returns resulting rbx
    ///   @param pmut_rcx the subindex used by CPUID, returns the resulting rcx
    ///   @param pmut_rdx returns resulting rdx
    ///
    extern "C" constexpr void
    intrinsic_cpuid_impl(
        gs_t const *const gs,
        bsl::uint64 *const pmut_rax,
        bsl::uint64 *const pmut_rbx,
        bsl::uint64 *const pmut_rcx,
        bsl::uint64 *const pmut_rdx) noexcept
    {
        if (bsl::unlikely(nullptr == gs)) {
            bsl::alert() << "gs is null\n" << bsl::here();
            return;
        }

        if (bsl::unlikely(nullptr == pmut_rax)) {
            bsl::alert() << "pmut_rax is null\n" << bsl::here();
            return;
        }

        if (bsl::unlikely(nullptr == pmut_rbx)) {
            bsl::alert() << "pmut_rbx is null\n" << bsl::here();
            return;
        }

        if (bsl::unlikely(nullptr == pmut_rcx)) {
            bsl::alert() << "pmut_rcx is null\n" << bsl::here();
            return;
        }

        if (bsl::unlikely(nullptr == pmut_rdx)) {
            bsl::alert() << "pmut_rdx is null\n" << bsl::here();
            return;
        }

        *pmut_rax = gs->cpuid_val.get();
        *pmut_rbx = gs->cpuid_val.get();
        *pmut_rcx = gs->cpuid_val.get();
        *pmut_rdx = gs->cpuid_val.get();
    }
}

#endif
