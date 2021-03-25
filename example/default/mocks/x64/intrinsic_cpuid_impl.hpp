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

#ifndef MOCKS_INTRINSIC_IMPL_PROTOTYPES_HPP
#define MOCKS_INTRINSIC_IMPL_PROTOTYPES_HPP

#include <gs_t.hpp>

#include <bsl/cstdint.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely_assert.hpp>

namespace example
{
    /// <!-- description -->
    ///   @brief Executes the CPUID instruction given the provided EAX and ECX
    ///     and returns the results
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs a pointer to the global storage to use
    ///   @param rax the index used by CPUID, returns resulting rax
    ///   @param rbx returns resulting rbx
    ///   @param rcx the subindex used by CPUID, returns the resulting rcx
    ///   @param rdx returns resulting rdx
    ///
    extern "C" constexpr void
    intrinsic_cpuid_impl(
        gs_t *const gs,
        bsl::uint64 *const rax,
        bsl::uint64 *const rbx,
        bsl::uint64 *const rcx,
        bsl::uint64 *const rdx) noexcept
    {
        if (bsl::unlikely_assert(nullptr == gs)) {
            bsl::alert() << "gs is null\n" << bsl::here();
            return;
        }

        if (bsl::unlikely_assert(nullptr == rax)) {
            bsl::alert() << "rax is null\n" << bsl::here();
            return;
        }

        if (bsl::unlikely_assert(nullptr == rbx)) {
            bsl::alert() << "rbx is null\n" << bsl::here();
            return;
        }

        if (bsl::unlikely_assert(nullptr == rcx)) {
            bsl::alert() << "rcx is null\n" << bsl::here();
            return;
        }

        if (bsl::unlikely_assert(nullptr == rdx)) {
            bsl::alert() << "rdx is null\n" << bsl::here();
            return;
        }

        *rax = gs->cpuid_val.get();
        *rbx = gs->cpuid_val.get();
        *rcx = gs->cpuid_val.get();
        *rdx = gs->cpuid_val.get();
    }
}

#endif
