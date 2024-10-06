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

#include <dispatch_esr.hpp>
#include <dispatch_syscall.hpp>
#include <ext_pool_t.hpp>
#include <huge_pool_t.hpp>
#include <intrinsic_t.hpp>
#include <mk_args_t.hpp>
#include <mk_main_t.hpp>
#include <page_pool_t.hpp>
#include <root_page_table_t.hpp>
#include <tls_t.hpp>
#include <vm_pool_t.hpp>
#include <vmexit_log_t.hpp>
#include <vmexit_loop.hpp>
#include <vp_pool_t.hpp>
#include <vs_pool_t.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/debug.hpp>

namespace mk
{
    /// @brief stores the TLS blocks used by the microkernel.
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    extern "C" constinit bsl::array<tls_t, HYPERVISOR_MAX_PPS.get()> g_mut_tls_blocks{};

    /// @brief stores a pointer to the debug ring provided by the loader
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    extern "C" constinit loader::debug_ring_t *g_pmut_mut_debug_ring{};

    /// @brief stores the vmexit log used by the microkernel
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    constinit inline vmexit_log_t g_mut_vmexit_log{};

    /// @brief stores the page_pool_t used by the microkernel
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    constinit inline page_pool_t g_mut_page_pool{};

    /// @brief stores the huge pool used by the microkernel
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    constinit inline huge_pool_t g_mut_huge_pool{};

    /// @brief stores the intrinsics used by the microkernel
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    constinit inline intrinsic_t g_mut_intrinsic{};

    /// @brief stores the vm_pool_t used by the microkernel
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    constinit inline vm_pool_t g_mut_vm_pool{};

    /// @brief stores the vp_pool_t used by the microkernel
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    constinit inline vp_pool_t g_mut_vp_pool{};

    /// @brief stores the vs_pool_t used by the microkernel
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    constinit inline vs_pool_t g_mut_vs_pool{};

    /// @brief stores the ext pool used by the microkernel
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    constinit inline ext_pool_t g_mut_ext_pool{};

    /// @brief stores the system RPT provided by the loader
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    constinit inline root_page_table_t g_mut_system_rpt{};

    /// @brief stores the microkernel's main class
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    constinit inline mk_main_t g_mut_mk_main{};

    /// <!-- description -->
    ///   @brief Remove me
    ///
    /// <!-- inputs/outputs -->
    ///   @param pmut_tls the current TLS block
    ///   @return Returns bsl::errc_success if the exception was handled,
    ///     bsl::errc_failure otherwise
    ///
    extern "C" [[nodiscard]] auto
    dispatch_esr_trampoline(tls_t *const pmut_tls) noexcept -> bsl::errc_type
    {
        bsl::expects(nullptr != pmut_tls);
        return dispatch_esr(*pmut_tls, g_mut_intrinsic);
    }

    /// <!-- description -->
    ///   @brief remove me
    ///
    /// <!-- inputs/outputs -->
    ///   @param pmut_tls the current TLS block
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    extern "C" [[nodiscard]] auto
    dispatch_syscall_trampoline(tls_t *const pmut_tls) noexcept -> bsl::uint64
    {
        bsl::expects(nullptr != pmut_tls);
        bsl::expects(nullptr != pmut_tls->ext);

        return dispatch_syscall(
                   *pmut_tls,
                   g_mut_page_pool,
                   g_mut_huge_pool,
                   g_mut_intrinsic,
                   g_mut_vm_pool,
                   g_mut_vp_pool,
                   g_mut_vs_pool,
                   g_mut_ext_pool,
                   g_mut_vmexit_log)
            .get();
    }

    /// <!-- description -->
    ///   @brief Provides the main entry point of the microkernel. This
    ///     function is called by the loader and is responsible for starting
    ///     the hypervisor on a specific core
    ///
    /// <!-- inputs/outputs -->
    ///   @param pmut_args the loader provided arguments to the microkernel.
    ///   @param pmut_tls the current TLS block
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    extern "C" [[nodiscard]] auto
    mk_main(loader::mk_args_t *const pmut_args, tls_t *const pmut_tls) noexcept -> bsl::errc_type
    {
        bsl::expects(nullptr != pmut_tls);
        bsl::expects(nullptr != pmut_args);

        return g_mut_mk_main.process(
            *pmut_tls,
            g_mut_page_pool,
            g_mut_huge_pool,
            g_mut_intrinsic,
            g_mut_vm_pool,
            g_mut_vp_pool,
            g_mut_vs_pool,
            g_mut_ext_pool,
            g_mut_system_rpt,
            g_mut_vmexit_log,
            *pmut_args);
    }
}
