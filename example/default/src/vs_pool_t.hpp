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

#ifndef VS_POOL_T_HPP
#define VS_POOL_T_HPP

#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_t.hpp>
#include <vs_t.hpp>

#include <bsl/array.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/finally.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace example
{
    /// @class example::vs_pool_t
    ///
    /// <!-- description -->
    ///   @brief Defines the extension's VS pool
    ///
    class vs_pool_t final
    {
        /// @brief stores the pool of vs_t objects
        bsl::array<vs_t, HYPERVISOR_MAX_VSS.get()> m_pool{};

        /// <!-- description -->
        ///   @brief Returns the vs_t associated with the provided vsid.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid the ID of the vs_t to get
        ///   @return Returns the vs_t associated with the provided vsid.
        ///
        [[nodiscard]] constexpr auto
        get_vs(bsl::safe_u16 const &vsid) noexcept -> vs_t *
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid < bsl::to_u16(m_pool.size()));
            return m_pool.at_if(bsl::to_idx(vsid));
        }

        /// <!-- description -->
        ///   @brief Returns the vs_t associated with the provided vsid.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid the ID of the vs_t to get
        ///   @return Returns the vs_t associated with the provided vsid.
        ///
        [[nodiscard]] constexpr auto
        get_vs(bsl::safe_u16 const &vsid) const noexcept -> vs_t const *
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid < bsl::to_u16(m_pool.size()));
            return m_pool.at_if(bsl::to_idx(vsid));
        }

    public:
        /// <!-- description -->
        ///   @brief Initializes this vs_pool_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        initialize(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic) noexcept
        {
            for (bsl::safe_idx mut_i{}; mut_i < m_pool.size(); ++mut_i) {
                m_pool.at_if(mut_i)->initialize(gs, tls, sys, intrinsic, bsl::to_u16(mut_i));
            }
        }

        /// <!-- description -->
        ///   @brief Release the vs_pool_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        release(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic) noexcept
        {
            for (auto &mut_vs : m_pool) {
                mut_vs.release(gs, tls, sys, intrinsic);
            }
        }

        /// <!-- description -->
        ///   @brief Allocates a VS and returns it's ID
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vpid the ID of the VP to assign the newly created VS to
        ///   @param ppid the ID of the PP to assign the newly created VS to
        ///   @return Returns the ID of the newly created VS on
        ///     success, or bsl::safe_u16::failure() on failure.
        ///
        [[nodiscard]] constexpr auto
        allocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &vpid,
            bsl::safe_u16 const &ppid) noexcept -> bsl::safe_u16
        {
            /// NOTE:
            /// - Ask the microkernel to create a VS and return the ID of the
            ///   newly created VS. We do not check in this function if the
            ///   provided vpid or ppid are valid as this is done by the
            ///   bf_vs_op_create_vs. We only need to check these types of
            ///   inputs at the point of use, and not when we are just passing
            ///   them to another function.
            ///

            auto const vsid{mut_sys.bf_vs_op_create_vs(vpid, ppid)};
            if (bsl::unlikely(vsid.is_invalid())) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_u16::failure();
            }

            /// NOTE:
            /// - The following is used in the event of an error. Basically,
            ///   whatever is in the bsl::finally will execute once the
            ///   function is returned from unless we explicitly call the
            ///   ignore() function, which we do at the end when all is good.
            ///

            bsl::finally mut_destroy_vs_on_error{[&mut_sys, &vsid]() noexcept -> void {
                bsl::discard(mut_sys.bf_vs_op_destroy_vs(vsid));
            }};

            /// NOTE:
            /// - Get the vs_t that was allocated by the microkernel.
            ///

            auto *const pmut_vs{m_pool.at_if(bsl::to_idx(vsid))};
            bsl::expects(nullptr != pmut_vs);

            /// NOTE:
            /// - Finally, we need to allocate the VS in our pool. This will
            ///   simply tell the VS which VP and PP it is assigned to. We
            ///   can use this in more complicated extensions, and it also
            ///   serves to make sure that we have not allocated the same VS
            ///   more than once.
            ///

            auto const ret{pmut_vs->allocate(gs, tls, mut_sys, intrinsic, vpid, ppid)};
            if (bsl::unlikely(ret.is_invalid())) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_u16::failure();
            }

            mut_destroy_vs_on_error.ignore();
            return vsid;
        }

        /// <!-- description -->
        ///   @brief Deallocates the requested vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vsid the ID of the vs_t to deallocate
        ///
        constexpr void
        deallocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &vsid) noexcept
        {
            this->get_vs(vsid)->deallocate(gs, tls, sys, intrinsic);
        }

        /// <!-- description -->
        ///   @brief Returns true if the requested vs_t is deallocated,
        ///     false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns true if the requested vs_t is deallocated,
        ///     false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_deallocated(bsl::safe_u16 const &vsid) const noexcept -> bool
        {
            return this->get_vs(vsid)->is_deallocated();
        }

        /// <!-- description -->
        ///   @brief Returns true if the requested vs_t is allocated,
        ///     false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns true if the requested vs_t is allocated,
        ///     false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_allocated(bsl::safe_u16 const &vsid) const noexcept -> bool
        {
            return this->get_vs(vsid)->is_allocated();
        }
    };
}

#endif
