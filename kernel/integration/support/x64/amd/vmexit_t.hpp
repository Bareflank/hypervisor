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

#ifndef VMEXIT_T_HPP
#define VMEXIT_T_HPP

#include <bf_debug_ops.hpp>
#include <bf_syscall_t.hpp>
#include <cpuid_commands.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_t.hpp>
#include <vp_pool_t.hpp>
#include <vs_pool_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace example
{
    /// @class example::vmexit_t
    ///
    /// <!-- description -->
    ///   @brief Defines the extension's VMExit handler
    ///
    class vmexit_t final
    {
    public:
        /// <!-- description -->
        ///   @brief Initializes this vmexit_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vp_pool the vp_pool_t to use
        ///   @param vs_pool the vs_pool_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        initialize(
            gs_t &gs,
            tls_t &tls,
            syscall::bf_syscall_t &sys,
            intrinsic_t &intrinsic,
            vp_pool_t &vp_pool,
            vs_pool_t &vs_pool) noexcept -> bsl::errc_type
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);
            bsl::discard(vp_pool);
            bsl::discard(vs_pool);

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Release the vmexit_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vp_pool the vp_pool_t to use
        ///   @param vs_pool the vs_pool_t to use
        ///
        static constexpr void
        release(
            gs_t &gs,
            tls_t &tls,
            syscall::bf_syscall_t &sys,
            intrinsic_t &intrinsic,
            vp_pool_t &vp_pool,
            vs_pool_t &vs_pool) noexcept
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);
            bsl::discard(vp_pool);
            bsl::discard(vs_pool);
        }

        /// <!-- description -->
        ///   @brief Handles the CPUID VMexit
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vp_pool the vp_pool_t to use
        ///   @param vs_pool the vs_pool_t to use
        ///   @param vsid the ID of the VS that generated the VMExit
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        handle_cpuid(
            gs_t &gs,
            tls_t &tls,
            syscall::bf_syscall_t &sys,
            intrinsic_t &intrinsic,
            vp_pool_t &vp_pool,
            vs_pool_t &vs_pool,
            bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(vp_pool);
            bsl::discard(vs_pool);

            bsl::errc_type ret{};

            auto rax{sys.bf_tls_rax()};
            auto rbx{sys.bf_tls_rbx()};
            auto rcx{sys.bf_tls_rcx()};
            auto rdx{sys.bf_tls_rdx()};

            if (loader::CPUID_COMMAND_EAX == bsl::to_u32_unsafe(rax)) {
                switch (bsl::to_u32_unsafe(rcx).get()) {
                    case loader::CPUID_COMMAND_ECX_STOP.get(): {
                        sys.bf_tls_set_rax(loader::CPUID_COMMAND_RAX_SUCCESS);

                        ret = sys.bf_vs_op_advance_ip(vsid);
                        if (bsl::unlikely(!ret)) {
                            bsl::print<bsl::V>() << bsl::here();
                            return ret;
                        }

                        return sys.bf_vs_op_promote(vsid);
                    }

                    case loader::CPUID_COMMAND_ECX_REPORT_ON.get(): {
                        break;
                    }

                    case loader::CPUID_COMMAND_ECX_REPORT_OFF.get(): {
                        break;
                    }

                    default: {
                        bsl::error() << "unsupported cpuid command "    // --
                                     << bsl::hex(rcx)                   // --
                                     << bsl::endl                       // --
                                     << bsl::here();                    // --

                        break;
                    }
                }

                return sys.bf_vs_op_advance_ip_and_run_current();
            }

            intrinsic.cpuid(rax, rbx, rcx, rdx);

            sys.bf_tls_set_rax(rax);
            sys.bf_tls_set_rbx(rbx);
            sys.bf_tls_set_rcx(rcx);
            sys.bf_tls_set_rdx(rdx);

            return sys.bf_vs_op_advance_ip_and_run_current();
        }

        /// <!-- description -->
        ///   @brief Dispatches the VMExit.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vp_pool the vp_pool_t to use
        ///   @param vs_pool the vs_pool_t to use
        ///   @param vsid the ID of the VS that generated the VMExit
        ///   @param exit_reason the exit reason associated with the VMExit
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        dispatch(
            gs_t &gs,
            tls_t &tls,
            syscall::bf_syscall_t &sys,
            intrinsic_t &intrinsic,
            vp_pool_t &vp_pool,
            vs_pool_t &vs_pool,
            bsl::safe_u16 const &vsid,
            bsl::safe_u64 const &exit_reason) noexcept -> bsl::errc_type
        {
            constexpr auto exit_reason_cpuid{0x72_u64};

            switch (exit_reason.get()) {
                case exit_reason_cpuid.get(): {
                    return handle_cpuid(gs, tls, sys, intrinsic, vp_pool, vs_pool, vsid);
                }

                default: {
                    break;
                }
            }

            bsl::error() << "unsupported vmexit "    // --
                         << bsl::hex(exit_reason)    // --
                         << bsl::endl                // --
                         << bsl::here();             // --

            return bsl::errc_failure;
        }
    };
}

#endif
