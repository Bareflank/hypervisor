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

#ifndef MK_MAIN_HPP
#define MK_MAIN_HPP

#include <bf_constants.hpp>
#include <ext_pool_t.hpp>
#include <huge_pool_t.hpp>
#include <intrinsic_t.hpp>
#include <page_pool_t.hpp>
#include <root_page_table_t.hpp>
#include <tls_t.hpp>
#include <vm_pool_t.hpp>
#include <vmexit_loop_entry.hpp>
#include <vp_pool_t.hpp>
#include <vps_pool_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/finally_assert.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>
#include <bsl/unlikely_assert.hpp>

namespace mk
{
    /// @class mk::mk_main_t
    ///
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
        /// @brief stores the root VMID
        bsl::safe_uint16 m_root_vmid{};
        /// @brief stores the registered VMExit handler
        void *m_ext_vmexit{};
        /// @brief stores the registered fast fail handler
        void *m_ext_fail{};

        /// <!-- description -->
        ///   @brief Verifies that the args and the resulting TLS block
        ///     make sense. The trampoline code has to fill in a lot of
        ///     the TLS block to bootstrap, so this provides some simple
        ///     sanity checks where possible.
        ///
        /// <!-- inputs/outputs -->
        ///   @param args the loader provided arguments to the microkernel.
        ///   @param tls the current TLS block
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        verify_args(loader::mk_args_t *const args, tls_t &tls) noexcept -> bsl::errc_type
        {
            if (args->ppid == syscall::BF_BS_PPID) {
                if (bsl::unlikely_assert(syscall::BF_INVALID_ID != tls.active_vmid)) {
                    bsl::error() << "cannot initialize the BSP more than once"    // --
                                 << bsl::endl                                     // --
                                 << bsl::here();                                  // --

                    return bsl::errc_failure;
                }

                bsl::touch();
            }
            else {
                if (bsl::unlikely_assert(syscall::BF_INVALID_ID != tls.active_vmid)) {
                    bsl::error() << "cannot initialize the AP more than once"    // --
                                 << bsl::endl                                    // --
                                 << bsl::here();                                 // --

                    return bsl::errc_failure;
                }

                if (bsl::unlikely_assert(!m_root_vmid)) {
                    bsl::error() << "cannot initialize an AP due to previous failure"    // --
                                 << bsl::endl                                            // --
                                 << bsl::here();                                         // --

                    return bsl::errc_failure;
                }

                bsl::touch();
            }

            if (bsl::unlikely_assert(bsl::to_u16(tls.ppid) != args->ppid)) {
                bsl::error() << "tls.ppid ["                          // --
                             << bsl::hex(tls.ppid)                    // --
                             << "] doesn't match the args->ppid ["    // --
                             << bsl::hex(args->ppid)                  // --
                             << "]"                                   // --
                             << bsl::endl                             // --
                             << bsl::here();                          // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID == tls.ppid)) {
                bsl::error() << "tls.ppid ["                          // --
                             << bsl::hex(tls.ppid)                    // --
                             << "] doesn't match the args->ppid ["    // --
                             << bsl::hex(args->ppid)                  // --
                             << "]"                                   // --
                             << bsl::endl                             // --
                             << bsl::here();                          // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(bsl::to_u16(tls.online_pps) != args->online_pps)) {
                bsl::error() << "tls.online_pps ["                          // --
                             << bsl::hex(tls.online_pps)                    // --
                             << "] doesn't match the args->online_pps ["    // --
                             << bsl::hex(args->online_pps)                  // --
                             << "]"                                         // --
                             << bsl::endl                                   // --
                             << bsl::here();                                // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(tls.online_pps > bsl::to_u16(HYPERVISOR_MAX_PPS))) {
                bsl::error() << "tls.online_pps ["                            // --
                             << bsl::hex(tls.online_pps)                      // --
                             << "] is not less or equal to than the max ["    // --
                             << bsl::hex(HYPERVISOR_MAX_PPS)                  // --
                             << "]"                                           // --
                             << bsl::endl                                     // --
                             << bsl::here();                                  // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(!(bsl::to_u16(args->ppid) < args->online_pps))) {
                bsl::error() << "the args->ppid ["                         // --
                             << bsl::hex(args->ppid)                       // --
                             << "] is not less than args->online_pps ["    // --
                             << bsl::hex(args->online_pps)                 // --
                             << "]"                                        // --
                             << bsl::endl                                  // --
                             << bsl::here();                               // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(nullptr == args->mk_state)) {
                bsl::error() << "args->mk_state is null"    // --
                             << bsl::endl                   // --
                             << bsl::here();                // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(nullptr == args->root_vp_state)) {
                bsl::error() << "args->root_vp_state is null"    // --
                             << bsl::endl                        // --
                             << bsl::here();                     // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(nullptr == args->debug_ring)) {
                bsl::error() << "args->debug_ring is null"    // --
                             << bsl::endl                     // --
                             << bsl::here();                  // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(args->mk_elf_file.empty())) {
                bsl::error() << "args->mk_elf_file is empty"    // --
                             << bsl::endl                       // --
                             << bsl::here();                    // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(args->mk_elf_file.size().is_zero())) {
                bsl::error() << "args->mk_elf_file's size is zero"    // --
                             << bsl::endl                             // --
                             << bsl::here();                          // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(!(args->mk_elf_file.size() < HYPERVISOR_MK_CODE_SIZE))) {
                bsl::error() << "args->mk_elf_file's size is too big"    // --
                             << bsl::endl                                // --
                             << bsl::here();                             // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(args->ext_elf_files.front().empty())) {
                bsl::error() << "args->ext_elf_files.front() is empty"    // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(args->ext_elf_files.front().size().is_zero())) {
                bsl::error() << "args->ext_elf_files.front()'s size is zero"    // --
                             << bsl::endl                                       // --
                             << bsl::here();                                    // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(
                    !(args->ext_elf_files.front().size() < HYPERVISOR_MK_CODE_SIZE))) {
                bsl::error() << "args->ext_elf_files.front()'s size is too big"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(nullptr == args->rpt)) {
                bsl::error() << "args->rpt is null"    // --
                             << bsl::endl              // --
                             << bsl::here();           // --

                return bsl::errc_failure;
            }

            constexpr auto null_address{0_umax};
            if (bsl::unlikely_assert(null_address == args->rpt_phys)) {
                bsl::error() << "args->rpt_phys is 0"    // --
                             << bsl::endl                // --
                             << bsl::here();             // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(args->page_pool.empty())) {
                bsl::error() << "args->page_pool is empty"    // --
                             << bsl::endl                     // --
                             << bsl::here();                  // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(args->page_pool.size().is_zero())) {
                bsl::error() << "args->page_pool's size is zero"    // --
                             << bsl::endl                           // --
                             << bsl::here();                        // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(args->page_pool.size() < HYPERVISOR_PAGE_SIZE)) {
                bsl::error() << "args->page_pool's size is too small"    // --
                             << bsl::endl                                // --
                             << bsl::here();                             // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(args->huge_pool.empty())) {
                bsl::error() << "args->huge_pool is empty"    // --
                             << bsl::endl                     // --
                             << bsl::here();                  // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(args->huge_pool.size().is_zero())) {
                bsl::error() << "args->huge_pool's size is zero"    // --
                             << bsl::endl                           // --
                             << bsl::here();                        // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(args->huge_pool.size() < HYPERVISOR_PAGE_SIZE)) {
                bsl::error() << "args->huge_pool's size is too small"    // --
                             << bsl::endl                                // --
                             << bsl::here();                             // --

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets the extension stack pointer given a TLS block,
        ///     based on what PP we are currently executing on.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///
        static constexpr void
        set_extension_sp(tls_t &tls) noexcept
        {
            constexpr auto stack_addr{HYPERVISOR_EXT_STACK_ADDR};
            constexpr auto stack_size{HYPERVISOR_EXT_STACK_SIZE};

            auto const offs{(stack_size + HYPERVISOR_PAGE_SIZE) * bsl::to_umax(tls.ppid)};
            tls.sp = (stack_addr + offs + stack_size).get();
        }

        /// <!-- description -->
        ///   @brief Sets the extension TLS pointer given a TLS block,
        ///     based on what PP we are currently executing on.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///
        static constexpr void
        set_extension_tp(tls_t &tls, intrinsic_t &intrinsic) noexcept
        {
            constexpr auto tls_addr{HYPERVISOR_EXT_TLS_ADDR};
            constexpr auto tls_size{HYPERVISOR_EXT_TLS_SIZE};

            auto const offs{(tls_size + HYPERVISOR_PAGE_SIZE) * bsl::to_umax(tls.ppid)};
            tls.tp = (tls_addr + offs + HYPERVISOR_PAGE_SIZE).get();

            intrinsic.set_tp(tls.tp);
        }

        /// <!-- description -->
        ///   @brief Initialize all of the global resources the microkernel
        ///     depends on.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param huge_pool the huge_pool_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vm_pool the vm_pool_t to use
        ///   @param vp_pool the vp_pool_t to use
        ///   @param vps_pool the vps_pool_t to use
        ///   @param ext_pool the ext_pool_t to use
        ///   @param system_rpt the system RPT provided by the loader
        ///   @param args the loader provided arguments to the microkernel.
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(
            tls_t &tls,
            page_pool_t &page_pool,
            huge_pool_t &huge_pool,
            intrinsic_t &intrinsic,
            vm_pool_t &vm_pool,
            vp_pool_t &vp_pool,
            vps_pool_t &vps_pool,
            ext_pool_t &ext_pool,
            root_page_table_t &system_rpt,
            loader::mk_args_t *const args) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};

            bsl::print() << bsl::mag << R"( ___                __ _           _        )"
                         << bsl::endl;
            bsl::print() << bsl::mag << R"(| _ ) __ _ _ _ ___ / _| |__ _ _ _ | |__     )"
                         << bsl::endl;
            bsl::print() << bsl::mag << R"(| _ \/ _` | '_/ -_)  _| / _` | ' \| / /     )"
                         << bsl::endl;
            bsl::print() << bsl::mag << R"(|___/\__,_|_| \___|_| |_\__,_|_||_|_\_\     )"
                         << bsl::endl;
            bsl::print() << bsl::rst << bsl::endl;
            bsl::print() << bsl::grn << "Please give us a star on: ";
            bsl::print() << bsl::rst << "https://github.com/Bareflank/hypervisor";
            bsl::print() << bsl::rst << bsl::endl;
            bsl::print() << bsl::ylw << "=================================";
            bsl::print() << bsl::ylw << "=================================";
            bsl::print() << bsl::rst << bsl::endl;
            bsl::print() << bsl::rst << bsl::endl;

            page_pool.initialize(args->page_pool);
            huge_pool.initialize(args->huge_pool);

            ret = system_rpt.initialize(tls, page_pool);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = system_rpt.add_tables(tls, args->rpt);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = vps_pool.initialize(tls, page_pool);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = vp_pool.initialize(tls, vps_pool);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = ext_pool.initialize(tls, page_pool, system_rpt, args->ext_elf_files);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = vm_pool.initialize(tls, page_pool, ext_pool, vp_pool);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            m_root_vmid = vm_pool.allocate(tls, page_pool, ext_pool);
            if (bsl::unlikely(!m_root_vmid)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = vm_pool.set_active(tls, m_root_vmid);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = ext_pool.start(tls, intrinsic);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

    public:
        /// <!-- description -->
        ///   @brief Process the mk_args_t provided by the loader.
        ///     If the user provided command succeeds, this function
        ///     will return bsl::exit_success, otherwise this function
        ///     will return bsl::exit_failure.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param huge_pool the huge_pool_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vm_pool the vm_pool_t to use
        ///   @param vp_pool the vp_pool_t to use
        ///   @param vps_pool the vps_pool_t to use
        ///   @param ext_pool the ext_pool_t to use
        ///   @param system_rpt the system RPT provided by the loader
        ///   @param args the loader provided arguments to the microkernel.
        ///   @return If the user provided command succeeds, this function
        ///     will return bsl::exit_success, otherwise this function
        ///     will return bsl::exit_failure.
        ///
        [[nodiscard]] constexpr auto
        process(
            tls_t &tls,
            page_pool_t &page_pool,
            huge_pool_t &huge_pool,
            intrinsic_t &intrinsic,
            vm_pool_t &vm_pool,
            vp_pool_t &vp_pool,
            vps_pool_t &vps_pool,
            ext_pool_t &ext_pool,
            root_page_table_t &system_rpt,
            loader::mk_args_t *const args) noexcept -> bsl::exit_code
        {
            bsl::errc_type ret{};

            bsl::finally_assert reset_root_vmid_on_error{[this]() noexcept -> void {
                m_root_vmid = bsl::safe_uint16::failure();
            }};

            ret = this->verify_args(args, tls);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::exit_failure;
            }

            set_extension_sp(tls);
            set_extension_tp(tls, intrinsic);

            if (args->ppid == syscall::BF_BS_PPID) {
                ret = this->initialize(
                    tls,
                    page_pool,
                    huge_pool,
                    intrinsic,
                    vm_pool,
                    vp_pool,
                    vps_pool,
                    ext_pool,
                    system_rpt,
                    args);

                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::exit_failure;
                }

                m_ext_vmexit = tls.ext_vmexit;
                if (bsl::unlikely(nullptr == m_ext_vmexit)) {
                    bsl::error() << "a vmexit handler has not been registered"    // --
                                 << bsl::endl                                     // --
                                 << bsl::here();                                  // --

                    return bsl::exit_failure;
                }

                m_ext_fail = tls.ext_fail;
                if (bsl::unlikely(nullptr == m_ext_fail)) {
                    bsl::error() << "a fast fail handler has not been registered"    // --
                                 << bsl::endl                                        // --
                                 << bsl::here();                                     // --

                    return bsl::exit_failure;
                }

                bsl::touch();
            }
            else {
                ret = vm_pool.set_active(tls, m_root_vmid);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::exit_failure;
                }

                tls.ext_vmexit = m_ext_vmexit;
                tls.ext_fail = m_ext_fail;
            }

            ret = ext_pool.bootstrap(tls, intrinsic);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::exit_failure;
            }

            if (bsl::unlikely(syscall::BF_INVALID_ID == tls.active_extid)) {
                bsl::error() << "bf_vps_op_run was never executed by an extension"    // --
                             << bsl::endl                                             // --
                             << bsl::here();                                          // --

                return bsl::exit_failure;
            }

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID == tls.active_vmid)) {
                bsl::error() << "bf_vps_op_run was never executed by an extension"    // --
                             << bsl::endl                                             // --
                             << bsl::here();                                          // --

                return bsl::exit_failure;
            }

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID == tls.active_vpid)) {
                bsl::error() << "bf_vps_op_run was never executed by an extension"    // --
                             << bsl::endl                                             // --
                             << bsl::here();                                          // --

                return bsl::exit_failure;
            }

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID == tls.active_vpsid)) {
                bsl::error() << "bf_vps_op_run was never executed by an extension"    // --
                             << bsl::endl                                             // --
                             << bsl::here();                                          // --

                return bsl::exit_failure;
            }

            if (bsl::unlikely_assert(nullptr == tls.active_rpt)) {
                bsl::error() << "bf_vps_op_run was never executed by an extension"    // --
                             << bsl::endl                                             // --
                             << bsl::here();                                          // --

                return bsl::exit_failure;
            }

            if (bsl::unlikely(vmexit_loop_entry() != bsl::exit_success)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::exit_failure;
            }

            // Unreachable. Only used for unit testing

            reset_root_vmid_on_error.ignore();
            return bsl::exit_success;
        }
    };
}

#endif
