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

#ifndef INTRINSIC_HPP
#define INTRINSIC_HPP

#include <gs_t.hpp>
#include <intrinsic_cpuid_impl.hpp>
#include <tls_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/safe_integral.hpp>

namespace syscall
{
    /// <!-- description -->
    ///   @brief Provides raw access to intrinsics. Instead of using global
    ///     functions, the intrinsics class provides a means for the rest of
    ///     the extension to mock the intrinsics when needed during testing.
    ///
    class intrinsic_t final
    {
    public:
        /// <!-- description -->
        ///   @brief Executes the CPUID instruction given the provided
        ///     EAX and ECX and returns the results.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_rax the index used by CPUID, returns resulting rax
        ///   @param mut_rbx returns resulting rbx
        ///   @param mut_rcx the subindex used by CPUID, returns the resulting rcx
        ///   @param mut_rdx returns resulting rdx
        ///
        static constexpr void
        cpuid(
            gs_t const &gs,
            tls_t const &tls,
            bsl::safe_u64 &mut_rax,
            bsl::safe_u64 &mut_rbx,
            bsl::safe_u64 &mut_rcx,
            bsl::safe_u64 &mut_rdx) noexcept
        {
            bsl::discard(tls);
            intrinsic_cpuid_impl(
                &gs, mut_rax.data(), mut_rbx.data(), mut_rcx.data(), mut_rdx.data());
        }
    };
}

#endif
