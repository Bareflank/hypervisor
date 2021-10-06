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

#ifndef MOCKS_MK_MAIN_HPP
#define MOCKS_MK_MAIN_HPP

#include <ext_pool_t.hpp>
#include <huge_pool_t.hpp>
#include <intrinsic_t.hpp>
#include <mk_args_t.hpp>
#include <page_pool_t.hpp>
#include <root_page_table_t.hpp>
#include <tls_t.hpp>
#include <vm_pool_t.hpp>
#include <vmexit_log_t.hpp>
#include <vp_pool_t.hpp>
#include <vs_pool_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Provide the main entry point for the microkernel. The
    ///     microkernel actually starts in the _start function, and immediately
    ///     creates this class and calls its process() function to boot the
    ///     microkernel, start the extensions and eventually demote the CPU.
    ///     Like the other main classes, this class serves to encapsulate
    ///     the entry logic into something that can be easily tested with no
    ///     dependencies on global resources.
    ///
    class mk_main_t final
    {
    public:
        /// <!-- description -->
        ///   @brief Process the mk_args_t provided by the loader.
        ///     If the user provided command succeeds, this function
        ///     will return bsl::errc_success, otherwise this function
        ///     will return bsl::errc_failure.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param huge_pool the huge_pool_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vm_pool the vm_pool_t to use
        ///   @param vp_pool the vp_pool_t to use
        ///   @param vs_pool the vs_pool_t to use
        ///   @param ext_pool the ext_pool_t to use
        ///   @param system_rpt the system RPT provided by the loader
        ///   @param log the VMExit log to use
        ///   @param args the loader provided arguments to the microkernel.
        ///   @return If the user provided command succeeds, this function
        ///     will return bsl::errc_success, otherwise this function
        ///     will return bsl::errc_failure.
        ///
        [[nodiscard]] static constexpr auto
        process(
            tls_t const &tls,
            page_pool_t const &page_pool,
            huge_pool_t const &huge_pool,
            intrinsic_t const &intrinsic,
            vm_pool_t const &vm_pool,
            vp_pool_t const &vp_pool,
            vs_pool_t const &vs_pool,
            ext_pool_t const &ext_pool,
            root_page_table_t const &system_rpt,
            vmexit_log_t const &log,
            loader::mk_args_t const &args) noexcept -> bsl::errc_type
        {
            bsl::discard(tls);
            bsl::discard(page_pool);
            bsl::discard(huge_pool);
            bsl::discard(intrinsic);
            bsl::discard(vm_pool);
            bsl::discard(vp_pool);
            bsl::discard(vs_pool);
            bsl::discard(ext_pool);
            bsl::discard(system_rpt);
            bsl::discard(log);
            bsl::discard(args);

            return tls.test_ret;
        }
    };
}

#endif
