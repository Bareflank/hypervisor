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

#ifndef MOCKS_INTRINSIC_HPP
#define MOCKS_INTRINSIC_HPP

#include <gs_t.hpp>
#include <tls_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>

namespace example
{
    /// @class example::intrinsic_t
    ///
    /// <!-- description -->
    ///   @brief Provides raw access to intrinsics used for unit testing.
    ///     Specifically, this version is architecture specific.
    ///
    class intrinsic_t final
    {
        /// @brief stores the return value for initialize
        bsl::errc_type m_initialize{};
        /// @brief stores the return value for eax with cpuid
        bsl::safe_uint32 m_eax{};
        /// @brief stores the return value for ebx with cpuid
        bsl::safe_uint32 m_ebx{};
        /// @brief stores the return value for ecx with cpuid
        bsl::safe_uint32 m_ecx{};
        /// @brief stores the return value for edx with cpuid
        bsl::safe_uint32 m_edx{};

    public:
        /// <!-- description -->
        ///   @brief Initializes this intrinsic_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(gs_t const &gs, tls_t const &tls) noexcept -> bsl::errc_type
        {
            bsl::discard(gs);
            bsl::discard(tls);

            return m_initialize;
        }

        /// <!-- description -->
        ///   @brief Sets the return value of initialize.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param errc the bsl::errc_type to return when executing
        ///     initialize
        ///
        constexpr void
        set_initialize(bsl::errc_type const &errc) noexcept
        {
            m_initialize = errc;
        }

        /// <!-- description -->
        ///   @brief Release the intrinsic_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///
        static constexpr void
        release(gs_t const &gs, tls_t const &tls) noexcept
        {
            bsl::discard(gs);
            bsl::discard(tls);
        }

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
        constexpr void
        cpuid(
            gs_t const &gs,
            tls_t const &tls,
            bsl::safe_uint64 &mut_rax,
            bsl::safe_uint64 &mut_rbx,
            bsl::safe_uint64 &mut_rcx,
            bsl::safe_uint64 &mut_rdx) const noexcept
        {
            bsl::discard(gs);
            bsl::discard(tls);

            constexpr auto mask{0xFFFFFFFF00000000_u64};

            mut_rax = ((mut_rax & mask) | bsl::to_u64(m_eax));
            mut_rbx = ((mut_rbx & mask) | bsl::to_u64(m_ebx));
            mut_rcx = ((mut_rcx & mask) | bsl::to_u64(m_ecx));
            mut_rdx = ((mut_rdx & mask) | bsl::to_u64(m_edx));
        }

        /// <!-- description -->
        ///   @brief Sets the return value of cpuid.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param eax the value to return from cpuid for eax
        ///   @param ebx the value to return from cpuid for ebx
        ///   @param ecx the value to return from cpuid for ecx
        ///   @param edx the value to return from cpuid for edx
        ///
        constexpr void
        set_cpuid(
            bsl::safe_uint32 const &eax,
            bsl::safe_uint32 const &ebx,
            bsl::safe_uint32 const &ecx,
            bsl::safe_uint32 const &edx) noexcept
        {
            m_eax = eax;
            m_ebx = ebx;
            m_ecx = ecx;
            m_edx = edx;
        }
    };
}

#endif
