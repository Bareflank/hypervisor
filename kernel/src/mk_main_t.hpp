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
#include <mk_args_t.hpp>
#include <page_pool_t.hpp>
#include <root_page_table_t.hpp>
#include <tls_t.hpp>
#include <vm_pool_t.hpp>
#include <vmexit_log_t.hpp>
#include <vmexit_loop.hpp>
#include <vp_pool_t.hpp>
#include <vs_pool_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/ensures.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/span.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

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
        /// @brief stores the root VMID
        bsl::safe_u16 m_root_vmid{syscall::BF_INVALID_ID};
        /// @brief stores the registered VMExit handler
        ext_t *m_ext_vmexit{};
        /// @brief stores the registered fast fail handler
        ext_t *m_ext_fail{};

        /// <!-- description -->
        ///   @brief Verifies that the mut_args and the resulting TLS block
        ///     make sense. The trampoline code has to fill in a lot of
        ///     the TLS block to bootstrap, so this provides some simple
        ///     sanity checks where possible.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_args the loader provided arguments to the microkernel.
        ///   @param mut_tls the current TLS block
        ///
        static constexpr void
        verify_mut_args(loader::mk_args_t &mut_args, tls_t &mut_tls) noexcept
        {
            /// NOTE:
            /// - The PPID should be set by the microkernel's entry logic in
            ///   the TLS block. This makes sure that happened correctly.
            ///

            bsl::expects(bsl::to_u16(mut_args.online_pps) == mut_tls.online_pps);
            bsl::expects(bsl::to_umx(mut_args.online_pps) <= HYPERVISOR_MAX_PPS);

            /// NOTE:
            /// - The online PPS should be set by the microkernel's entry logic
            ///   in the TLS block. This makes sure that happened correctly.
            ///

            bsl::expects(bsl::to_u16(mut_args.ppid) == mut_tls.ppid);
            bsl::expects(bsl::to_u16(mut_args.ppid) < mut_tls.online_pps);

            /// NOTE:
            /// - Verify that the rest of the fields make sense. They should
            ///   all be defined and valid.
            ///

            bsl::expects(nullptr != mut_args.mk_state);
            bsl::expects(nullptr != mut_args.root_vp_state);
            bsl::expects(nullptr != mut_args.debug_ring);
            bsl::expects(nullptr != mut_args.ext_elf_files.front());
            bsl::expects(nullptr != mut_args.rpt);
            bsl::expects(bsl::safe_umx::magic_0() != mut_args.rpt_phys);
            bsl::expects(mut_args.page_pool.is_valid());
            bsl::expects(mut_args.huge_pool.is_valid());
        }

        /// <!-- description -->
        ///   @brief Prints our fancy logo
        ///
        static constexpr void
        print_logo() noexcept
        {
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
        }

        /// <!-- description -->
        ///   @brief Sets the extension stack pointer given a TLS block,
        ///     based on what PP we are currently executing on.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///
        static constexpr void
        set_extension_sp(tls_t &mut_tls) noexcept
        {
            constexpr auto stack_addr{HYPERVISOR_EXT_STACK_ADDR};
            constexpr auto stack_size{HYPERVISOR_EXT_STACK_SIZE};
            constexpr auto stack_size_with_guard{stack_size + HYPERVISOR_PAGE_SIZE};

            /// NOTE:
            /// - Each extension has it's own address space, and their stacks
            ///   are all in the same location in each of their address spaces.
            /// - This function is calculating the stack pointer for each
            ///   extension for each PP.
            /// - Each PP is given it's own stack. This is similar to a thread
            ///   in userspace. They need to be able to execute symmetrically
            ///   and therefore, each extension has one stack per PP.
            /// - Although extensions have their own address spaces, similar to
            ///   userspace applications, their stacks all start at the
            ///   same location in this address space, and each PP has it's
            ///   own stack, each PP does NOT have it's own address space.
            ///   Again, this is similar to threads in userspace. Because of
            ///   this, each stack in an extension needs to have it's own
            ///   unique address in the extension's address space.
            /// - To make this all work, each extension is given one giant blob
            ///   of stack space starting at EXT_STACK_ADDR
            /// - For each PP, the ext_t allocates EXT_STACK_SIZE, and maps
            ///   it into the extension's address space, starting at
            ///   EXT_STACK_ADDR. Each time a PP's stack is mapped, the address
            ///   is incremented by EXT_STACK_SIZE + one page.
            /// - The extra page is a guard page. If a PP overruns it's stack
            ///   it will cause a page fault, at least preventing corruption
            ///   of the other stacks. Note that this will not prevent attacks
            ///   that jump passed this guard page. It is just there for sanity
            ///   purposes.
            /// - So, the TL;DR is, the stack space for an extension looks like
            ///   this:
            ///
            ///   --------------------   EXT_STACK_ADDR
            ///   |                  |
            ///   |    PP 0 Stack    |
            ///   |                  |
            ///   --------------------
            ///   |    Guard Page    |
            ///   --------------------
            ///   |                  |
            ///   |    PP 1 Stack    |
            ///   |                  |
            ///   --------------------
            ///   |    Guard Page    |
            ///   --------------------
            ///           ...
            ///
            /// - One question that might come up is, why do this math here
            ///   and not in the extension. This is because these addresses
            ///   are the same for all extensions. There is no need to do
            ///   these calculations more than once.
            ///

            auto const ppid{bsl::to_umx(mut_tls.ppid)};
            auto const sp{(stack_addr + (stack_size_with_guard * ppid) + stack_size).checked()};

            mut_tls.sp = sp.get();
            mut_tls.ext_sp = sp.get();
        }

        /// <!-- description -->
        ///   @brief Sets the extension stack pointer given a TLS block,
        ///     based on what PP we are currently executing on.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///
        static constexpr void
        set_extension_fail_sp(tls_t &mut_tls) noexcept
        {
            constexpr auto stack_addr{HYPERVISOR_EXT_FAIL_STACK_ADDR};
            constexpr auto stack_size{HYPERVISOR_EXT_FAIL_STACK_SIZE};
            constexpr auto stack_size_with_guard{stack_size + HYPERVISOR_PAGE_SIZE};

            /// NOTE:
            /// - Each extension has it's own address space, and their stacks
            ///   are all in the same location in each of their address spaces.
            /// - This function is calculating the stack pointer for each
            ///   extension for each PP.
            /// - Each PP is given it's own stack. This is similar to a thread
            ///   in userspace. They need to be able to execute symmetrically
            ///   and therefore, each extension has one stack per PP.
            /// - Although extensions have their own address spaces, similar to
            ///   userspace applications, their stacks all start at the
            ///   same location in this address space, and each PP has it's
            ///   own stack, each PP does NOT have it's own address space.
            ///   Again, this is similar to threads in userspace. Because of
            ///   this, each stack in an extension needs to have it's own
            ///   unique address in the extension's address space.
            /// - To make this all work, each extension is given one giant blob
            ///   of stack space starting at EXT_STACK_ADDR
            /// - For each PP, the ext_t allocates EXT_STACK_SIZE, and maps
            ///   it into the extension's address space, starting at
            ///   EXT_STACK_ADDR. Each time a PP's stack is mapped, the address
            ///   is incremented by EXT_STACK_SIZE + one page.
            /// - The extra page is a guard page. If a PP overruns it's stack
            ///   it will cause a page fault, at least preventing corruption
            ///   of the other stacks. Note that this will not prevent attacks
            ///   that jump passed this guard page. It is just there for sanity
            ///   purposes.
            /// - So, the TL;DR is, the stack space for an extension looks like
            ///   this:
            ///
            ///   --------------------   EXT_STACK_ADDR
            ///   |                  |
            ///   |    PP 0 Stack    |
            ///   |                  |
            ///   --------------------
            ///   |    Guard Page    |
            ///   --------------------
            ///   |                  |
            ///   |    PP 1 Stack    |
            ///   |                  |
            ///   --------------------
            ///   |    Guard Page    |
            ///   --------------------
            ///           ...
            ///
            /// - One question that might come up is, why do this math here
            ///   and not in the extension. This is because these addresses
            ///   are the same for all extensions. There is no need to do
            ///   these calculations more than once.
            ///

            auto const ppid{bsl::to_umx(mut_tls.ppid)};
            auto const sp{(stack_addr + (stack_size_with_guard * ppid) + stack_size).checked()};

            mut_tls.ext_fail_sp = sp.get();
        }

        /// <!-- description -->
        ///   @brief Sets the extension TLS pointer given a TLS block,
        ///     based on what PP we are currently executing on.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsic_t to use
        ///
        static constexpr void
        set_extension_tp(tls_t &mut_tls, intrinsic_t &mut_intrinsic) noexcept
        {
            constexpr auto tp_offs{HYPERVISOR_PAGE_SIZE};
            constexpr auto tls_addr{HYPERVISOR_EXT_TLS_ADDR};
            constexpr auto tls_size{HYPERVISOR_EXT_TLS_SIZE};
            constexpr auto tls_size_with_guard{tls_size + HYPERVISOR_PAGE_SIZE};

            /// NOTE:
            /// - Each extension has it's own address space, and their TLS
            ///   is all in the same location in each of their address spaces.
            /// - This function is calculating the TLS pointer for each
            ///   extension for each PP.
            /// - Each PP is given it's own TLS. This is similar to a thread
            ///   in userspace. They need to be able to execute symmetrically
            ///   and therefore, each extension has one TLS block per PP.
            /// - Although extensions have their own address spaces, similar to
            ///   userspace applications, their TLS blocks all start at the
            ///   same location in this address space, and each PP has it's
            ///   own TLS, each PP does NOT have it's own address space.
            ///   Again, this is similar to threads in userspace. Because of
            ///   this, each TLS block in an extension needs to have it's own
            ///   unique address in the extension's address space.
            /// - To make this all work, each extension is given one giant blob
            ///   of TLS space starting at EXT_TLS_ADDR
            /// - For each PP, the ext_t allocates EXT_TLS_SIZE, and maps
            ///   it into the extension's address space, starting at
            ///   EXT_TLS_ADDR. Each time a PP's stack is mapped, the address
            ///   is incremented by EXT_TLS_SIZE + one page.
            /// - The extra page is a guard page. If a PP overruns it's TLS
            ///   it will cause a page fault, at least preventing corruption
            ///   of the other blocks. Note that this will not prevent attacks
            ///   that jump passed this guard page. It is just there for sanity
            ///   purposes.
            /// - So, the TL;DR is, the TLS space for an extension looks like
            ///   this:
            ///
            ///   --------------------   EXT_TLS_ADDR
            ///   |                  |
            ///   |     PP 0 TLS     |
            ///   |                  |
            ///   --------------------
            ///   |    Guard Page    |
            ///   --------------------
            ///   |                  |
            ///   |     PP 1 TLS     |
            ///   |                  |
            ///   --------------------
            ///   |    Guard Page    |
            ///   --------------------
            ///           ...
            ///
            /// - One question that might come up is, why do this math here
            ///   and not in the extension. This is because these addresses
            ///   are the same for all extensions. There is no need to do
            ///   these calculations more than once.
            ///

            auto const ppid{bsl::to_umx(mut_tls.ppid)};
            auto const tp{(tls_addr + (tls_size_with_guard * ppid) + tp_offs).checked()};

            mut_tls.tp = tp.get();
            mut_intrinsic.set_tp(tp);
        }

        /// <!-- description -->
        ///   @brief Initialize the BSP which also initializes all of the
        ///     global resources used by the microkernel, and starts the
        ///     extensions.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param mut_huge_pool the huge_pool_t to use
        ///   @param mut_intrinsic the intrinsic_t to use
        ///   @param mut_vm_pool the vm_pool_t to use
        ///   @param mut_vp_pool the vp_pool_t to use
        ///   @param mut_vs_pool the vs_pool_t to use
        ///   @param mut_ext_pool the ext_pool_t to use
        ///   @param mut_system_rpt the system RPT provided by the loader
        ///   @param mut_args the loader provided arguments to the microkernel.
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize_bsp(
            tls_t &mut_tls,
            page_pool_t &mut_page_pool,
            huge_pool_t &mut_huge_pool,
            intrinsic_t &mut_intrinsic,
            vm_pool_t &mut_vm_pool,
            vp_pool_t &mut_vp_pool,
            vs_pool_t &mut_vs_pool,
            ext_pool_t &mut_ext_pool,
            root_page_table_t &mut_system_rpt,
            loader::mk_args_t &mut_args) noexcept -> bsl::errc_type
        {
            bsl::errc_type mut_ret{};

            mut_page_pool.initialize(mut_args.page_pool);
            mut_huge_pool.initialize(mut_args.huge_pool);

            mut_ret = mut_system_rpt.initialize(mut_tls, mut_page_pool);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            mut_system_rpt.add_tables(mut_tls, mut_args.rpt);

            mut_vs_pool.initialize();
            mut_vp_pool.initialize();
            mut_vm_pool.initialize();

            mut_ret = mut_ext_pool.initialize(
                mut_tls, mut_page_pool, mut_huge_pool, mut_system_rpt, mut_args.ext_elf_files);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            m_root_vmid = mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool);
            if (bsl::unlikely(m_root_vmid.is_invalid())) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            mut_vm_pool.set_active(mut_tls, m_root_vmid);

            mut_ret = mut_ext_pool.start(mut_tls, mut_intrinsic);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(nullptr == mut_tls.ext_vmexit)) {
                bsl::error() << "a vmexit handler was not registered\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(nullptr == mut_tls.ext_fail)) {
                bsl::error() << "a fail handler was not registered\n" << bsl::here();
                return bsl::errc_failure;
            }

            m_ext_vmexit = mut_tls.ext_vmexit;
            m_ext_fail = mut_tls.ext_fail;

            bsl::ensures(m_root_vmid == syscall::BF_ROOT_VMID);
            bsl::ensures(nullptr != m_ext_vmexit);
            bsl::ensures(nullptr != m_ext_fail);

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Initialize an AP.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_vm_pool the vm_pool_t to use
        ///
        constexpr void
        initialize_ap(tls_t &mut_tls, vm_pool_t &mut_vm_pool) noexcept
        {
            bsl::expects(m_root_vmid == syscall::BF_ROOT_VMID);
            bsl::expects(nullptr != m_ext_vmexit);
            bsl::expects(nullptr != m_ext_fail);

            mut_vm_pool.set_active(mut_tls, m_root_vmid);
            mut_tls.ext_vmexit = m_ext_vmexit;
            mut_tls.ext_fail = m_ext_fail;
        }

    public:
        /// <!-- description -->
        ///   @brief Process the mk_args_t provided by the loader.
        ///     If the user provided command succeeds, this function
        ///     will return bsl::errc_success, otherwise this function
        ///     will return bsl::errc_failure.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param mut_huge_pool the huge_pool_t to use
        ///   @param mut_intrinsic the intrinsic_t to use
        ///   @param mut_vm_pool the vm_pool_t to use
        ///   @param mut_vp_pool the vp_pool_t to use
        ///   @param mut_vs_pool the vs_pool_t to use
        ///   @param mut_ext_pool the ext_pool_t to use
        ///   @param mut_system_rpt the system RPT provided by the loader
        ///   @param mut_log the VMExit log to use
        ///   @param mut_args the loader provided arguments to the microkernel.
        ///   @return If the user provided command succeeds, this function
        ///     will return bsl::errc_success, otherwise this function
        ///     will return bsl::errc_failure.
        ///
        [[nodiscard]] constexpr auto
        process(
            tls_t &mut_tls,
            page_pool_t &mut_page_pool,
            huge_pool_t &mut_huge_pool,
            intrinsic_t &mut_intrinsic,
            vm_pool_t &mut_vm_pool,
            vp_pool_t &mut_vp_pool,
            vs_pool_t &mut_vs_pool,
            ext_pool_t &mut_ext_pool,
            root_page_table_t &mut_system_rpt,
            vmexit_log_t &mut_log,
            loader::mk_args_t &mut_args) noexcept -> bsl::errc_type
        {
            bsl::errc_type mut_ret{};

            /// NOTE:
            /// - Make sure that we have not already been loaded on this
            ///   PP. If we have, we have a problem.
            ///

            bsl::expects(syscall::BF_INVALID_ID == mut_tls.active_vmid);
            bsl::expects(syscall::BF_INVALID_ID == mut_tls.active_vpid);
            bsl::expects(syscall::BF_INVALID_ID == mut_tls.active_vsid);

            /// NOTE:
            /// - Verify that the arguments make sense. This is really there
            ///   to ensure the loader and the entry logic did their job
            ///   correctly.
            ///

            verify_mut_args(mut_args, mut_tls);

            /// NOTE:
            /// - Print our logo. We do this after we verify the arguments
            ///   because if there is an error with the arguments, the logo
            ///   many not be able to safely print.
            ///

            if (mut_args.ppid == syscall::BF_BS_PPID) {
                print_logo();
            }
            else {
                bsl::touch();
            }

            /// NOTE:
            /// - Set up the stack pointer and TLS pointer for all of the
            ///   extensions. Remember that each extension has the same
            ///   address space layout, so their SP and TP is the same for
            ///   each PP. If we add ALSR, this will have to be modified.
            ///

            set_extension_sp(mut_tls);
            set_extension_fail_sp(mut_tls);
            set_extension_tp(mut_tls, mut_intrinsic);

            /// NOTE:
            /// - Initialize the PP. How this is done depends on whether or
            ///   not the PP is the BSP.
            ///

            if (mut_args.ppid == syscall::BF_BS_PPID) {
                mut_ret = this->initialize_bsp(
                    mut_tls,
                    mut_page_pool,
                    mut_huge_pool,
                    mut_intrinsic,
                    mut_vm_pool,
                    mut_vp_pool,
                    mut_vs_pool,
                    mut_ext_pool,
                    mut_system_rpt,
                    mut_args);

                if (bsl::unlikely(!mut_ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }
            else {
                this->initialize_ap(mut_tls, mut_vm_pool);
            }

            /// NOTE:
            /// - Boostrap all of the PPs for all of the extensions. Once this
            ///   is done, we should be ready to start the hypervisor.
            ///

            mut_ret = mut_ext_pool.bootstrap(mut_tls, mut_intrinsic);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            /// NOTE:
            /// - Perform some last minute sanity checks.
            ///

            bsl::ensures(syscall::BF_INVALID_ID != mut_tls.ppid);
            bsl::ensures(syscall::BF_INVALID_ID != mut_tls.active_vmid);
            bsl::ensures(syscall::BF_INVALID_ID != mut_tls.active_vpid);
            bsl::ensures(syscall::BF_INVALID_ID != mut_tls.active_vsid);

            bsl::ensures(nullptr != mut_tls.active_rpt);
            bsl::ensures(syscall::BF_INVALID_ID != mut_tls.active_extid);

            /// NOTE:
            /// - Start the hypervisor.
            ///

            return vmexit_loop(mut_tls, mut_intrinsic, mut_vs_pool, mut_log);
        }
    };
}

#endif
