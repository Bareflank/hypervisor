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

#include <vmexit_loop_entry.hpp>

#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/finally.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// @class mk::mk_main
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
    /// <!-- template parameters -->
    ///   @tparam INTRINSIC_CONCEPT defines the type of intrinsics to use
    ///   @tparam PAGE_POOL_CONCEPT defines the type of page pool to use
    ///   @tparam HUGE_POOL_CONCEPT defines the type of huge pool to use
    ///   @tparam ROOT_PAGE_TABLE_CONCEPT defines the type of RPT pool to use
    ///   @tparam VPS_POOL_CONCEPT defines the type of VPS pool to use
    ///   @tparam VP_POOL_CONCEPT defines the type of VP pool to use
    ///   @tparam VM_POOL_CONCEPT defines the type of VM pool to use
    ///   @tparam EXT_POOL_CONCEPT defines the type of extension pool to use
    ///   @tparam PAGE_SIZE defines the size of a page
    ///   @tparam EXT_STACK_ADDR the address of the extension's stack
    ///   @tparam EXT_STACK_SIZE the size of the extension's stack
    ///   @tparam EXT_TLS_ADDR the address of the extension's TLS block
    ///   @tparam EXT_TLS_SIZE the size of the extension's TLS block
    ///
    template<
        typename INTRINSIC_CONCEPT,
        typename PAGE_POOL_CONCEPT,
        typename HUGE_POOL_CONCEPT,
        typename ROOT_PAGE_TABLE_CONCEPT,
        typename VPS_POOL_CONCEPT,
        typename VP_POOL_CONCEPT,
        typename VM_POOL_CONCEPT,
        typename EXT_POOL_CONCEPT,
        bsl::uintmax PAGE_SIZE,
        bsl::uintmax EXT_STACK_ADDR,
        bsl::uintmax EXT_STACK_SIZE,
        bsl::uintmax EXT_TLS_ADDR,
        bsl::uintmax EXT_TLS_SIZE>
    class mk_main final
    {
        /// @brief stores a reference to the intrinsics to use
        INTRINSIC_CONCEPT &m_intrinsic;
        /// @brief stores a reference to the page pool to use
        PAGE_POOL_CONCEPT &m_page_pool;
        /// @brief stores a reference to the huge pool to use
        HUGE_POOL_CONCEPT &m_huge_pool;
        /// @brief stores system RPT provided by the loader
        ROOT_PAGE_TABLE_CONCEPT &m_system_rpt;
        /// @brief stores a reference to the VPS pool to use
        VPS_POOL_CONCEPT &m_vps_pool;
        /// @brief stores a reference to the VP pool to use
        VP_POOL_CONCEPT &m_vp_pool;
        /// @brief stores a reference to the VM pool to use
        VM_POOL_CONCEPT &m_vm_pool;
        /// @brief stores a reference to the extension pool to use
        EXT_POOL_CONCEPT &m_ext_pool;

        /// @brief stores the extension pool's initialization status
        bool m_initialized;

        /// <!-- description -->
        ///   @brief Sets the extension stack pointer given a TLS block,
        ///     based on what PP we are currently executing on.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @param tls the current TLS block
        ///
        template<typename TLS_CONCEPT>
        constexpr void
        set_extension_sp(TLS_CONCEPT &tls) noexcept
        {
            constexpr bsl::safe_uintmax stack_addr{EXT_STACK_ADDR};
            constexpr bsl::safe_uintmax stack_size{EXT_STACK_SIZE};

            auto const offs{(stack_size + PAGE_SIZE) * bsl::to_umax(tls.ppid())};
            tls.sp = (stack_addr + offs + stack_size).get();
        }

        /// <!-- description -->
        ///   @brief Sets the extension TLS pointer given a TLS block,
        ///     based on what PP we are currently executing on.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @param tls the current TLS block
        ///
        template<typename TLS_CONCEPT>
        constexpr void
        set_extension_tp(TLS_CONCEPT &tls) noexcept
        {
            constexpr bsl::safe_uintmax tls_addr{EXT_TLS_ADDR};
            constexpr bsl::safe_uintmax tls_size{EXT_TLS_SIZE};

            auto const offs{(tls_size + PAGE_SIZE) * bsl::to_umax(tls.ppid())};
            tls.tp = (tls_addr + offs + PAGE_SIZE).get();

            m_intrinsic.set_tp(tls.tp);
        }

    public:
        /// @brief an alias for INTRINSIC_CONCEPT
        using intrinsic_type = INTRINSIC_CONCEPT;
        /// @brief an alias for PAGE_POOL_CONCEPT
        using page_pool_type = PAGE_POOL_CONCEPT;
        /// @brief an alias for HUGE_POOL_CONCEPT
        using huge_pool_type = HUGE_POOL_CONCEPT;
        /// @brief an alias for ROOT_PAGE_TABLE_CONCEPT
        using root_page_table_type = ROOT_PAGE_TABLE_CONCEPT;
        /// @brief an alias for VPS_POOL_CONCEPT
        using vps_pool_type = VPS_POOL_CONCEPT;
        /// @brief an alias for VP_POOL_CONCEPT
        using vp_pool_type = VP_POOL_CONCEPT;
        /// @brief an alias for VM_POOL_CONCEPT
        using vm_pool_type = VM_POOL_CONCEPT;
        /// @brief an alias for EXT_POOL_CONCEPT
        using ext_pool_type = EXT_POOL_CONCEPT;

        /// <!-- description -->
        ///   @brief Creates the microkernel's main class given the global
        ///     resources that the microkernel will rely on.
        ///
        /// <!-- inputs/outputs -->
        ///   @param intrinsic the intrinsics to use
        ///   @param page_pool the page pool to use
        ///   @param huge_pool the huge pool to use
        ///   @param system_rpt the system RPT provided by the loader
        ///   @param vps_pool the vps pool to use
        ///   @param vp_pool the vp pool to use
        ///   @param vm_pool the vm pool to use
        ///   @param ext_pool the extension pool to use
        ///
        constexpr mk_main(
            INTRINSIC_CONCEPT &intrinsic,
            PAGE_POOL_CONCEPT &page_pool,
            HUGE_POOL_CONCEPT &huge_pool,
            ROOT_PAGE_TABLE_CONCEPT &system_rpt,
            VPS_POOL_CONCEPT &vps_pool,
            VP_POOL_CONCEPT &vp_pool,
            VM_POOL_CONCEPT &vm_pool,
            EXT_POOL_CONCEPT &ext_pool) noexcept
            : m_intrinsic{intrinsic}
            , m_page_pool{page_pool}
            , m_huge_pool{huge_pool}
            , m_system_rpt{system_rpt}
            , m_vps_pool{vps_pool}
            , m_vp_pool{vp_pool}
            , m_vm_pool{vm_pool}
            , m_ext_pool{ext_pool}
            , m_initialized{}
        {}

        /// <!-- description -->
        ///   @brief Initialize all of the global resources the microkernel
        ///     depends on.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam MK_ARGS_CONCEPT the type of mk_args to use
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @param args the loader provided arguments to the microkernel.
        ///   @param tls the current TLS block
        ///   @return If the user provided command succeeds, this function
        ///     will return bsl::exit_success, otherwise this function
        ///     will return bsl::exit_failure.
        ///
        template<typename MK_ARGS_CONCEPT, typename TLS_CONCEPT>
        [[nodiscard]] constexpr auto
        initialize(MK_ARGS_CONCEPT *const args, TLS_CONCEPT &tls) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};

            if (m_initialized) {
                m_system_rpt.activate();

                ret = m_system_rpt.add_root_vp_state(args->root_vp_state);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                return bsl::errc_success;
            }

            bsl::print() << bsl::bold_magenta;
            bsl::print() << " ___                __ _           _         \n";
            bsl::print() << "| _ ) __ _ _ _ ___ / _| |__ _ _ _ | |__      \n";
            bsl::print() << "| _ \\/ _` | '_/ -_)  _| / _` | ' \\| / /    \n";
            bsl::print() << "|___/\\__,_|_| \\___|_| |_\\__,_|_||_|_\\_\\ \n";
            bsl::print() << "\n";
            bsl::print() << bsl::bold_green;
            bsl::print() << "Please give us a star on: ";
            bsl::print() << bsl::bold_white;
            bsl::print() << "https://github.com/Bareflank/hypervisor\n";
            bsl::print() << bsl::reset_color;
            bsl::print() << "=================================";
            bsl::print() << "=================================";
            bsl::print() << "\n";
            bsl::print() << "\n";

            ret = m_page_pool.initialize(args->page_pool, args->page_pool_base_virt);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_huge_pool.initialize(args->huge_pool, args->huge_pool_base_virt);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_system_rpt.initialize(&m_intrinsic, &m_page_pool);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_system_rpt.add_tables(args->rpt);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            m_system_rpt.activate();

            ret = m_system_rpt.add_root_vp_state(args->root_vp_state);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            /// NOTE:
            /// - At this point, if an error occurs, it will safely exit.
            ///   Prior to this point, if an error occurs, we will likely
            ///   see a page fault when exiting as the microkernel has no
            ///   way of restoring the GDT as the TSS busy bit cannot be
            ///   cleared without successfully mapping in the GDT. To fix
            ///   this issue, we would need to add a LOT of code to the
            ///   loader as it would need enough pageing logic to create
            ///   a temporary set of page tables capable of walking the
            ///   root OS's page tables to locate the physical address of
            ///   the GDT, since Linux will not provide that.
            ///

            ret = m_vps_pool.initialize();
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_vp_pool.initialize();
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_vm_pool.initialize();
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_ext_pool.initialize(args->ext_elf_files, args->online_pps);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_ext_pool.start(tls);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            m_initialized = true;
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Process the mk_args_t provided by the loader.
        ///     If the user provided command succeeds, this function
        ///     will return bsl::exit_success, otherwise this function
        ///     will return bsl::exit_failure.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam MK_ARGS_CONCEPT the type of mk_args to use
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @param args the loader provided arguments to the microkernel.
        ///   @param tls the current TLS block
        ///   @return If the user provided command succeeds, this function
        ///     will return bsl::exit_success, otherwise this function
        ///     will return bsl::exit_failure.
        ///
        template<typename MK_ARGS_CONCEPT, typename TLS_CONCEPT>
        [[nodiscard]] constexpr auto
        process(MK_ARGS_CONCEPT *const args, TLS_CONCEPT &tls) &noexcept -> bsl::exit_code
        {
            set_extension_sp(tls);
            set_extension_tp(tls);

            /// TODO:
            /// - Verify the incomings args
            ///

            if (bsl::unlikely(!this->initialize(args, tls))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::exit_failure;
            }

            if (bsl::unlikely(!m_ext_pool.bootstrap(tls))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::exit_failure;
            }

            /// TODO:
            /// - Need a way to ensure that vps_run was executed before
            ///   getting here. Otherwise, nothing at this point makes
            ///   any sense.
            ///

            if (bsl::unlikely(vmexit_loop_entry() != bsl::exit_success)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::exit_failure;
            }

            return bsl::exit_success;

            // Tasks:
            // [x] implement page_pool_t
            // [x] implement page_t
            // [x] implement tls_t
            // [x] implement thread_id for debugging in BSL
            // [x] implement dump_vmm
            // [x] implement ELF loader in C++
            // [x] implement vps_pool_t
            // [x] implement vps_t
            // [x] implement vp_pool_t
            // [x] implement vp_t
            // [x] implement vm_pool_t
            // [x] implement vm_t
            // [x] implement root_page_table_t
            // [x] implement configurable constants from CMake
            // [x] implement clang-format to reorder headers
            // [x] implement smep/smap lock
            // [x] implement mk stack for syscalls
            // [x] implement bsl::hex
            // [x] implement _start for extensions
            // [x] implement bsl platform logic for extensions
            // [x] implement simple debug ops
            // [x] implement control ops
            // [x] implement handle ops
            // [x] implement ext_pool_t
            // [x] implement ext_t
            // [x] implement exception handlers
            // [x] implement syscall exception safety
            // [x] implement extension failure reporting to call_ext
            // [x] implement esr error code logic
            // [x] implement esr.hpp
            // [x] implement extension ELF TLS support
            // [x] implement some refactoring on the ext_t class
            // [x] implement unwind routines for all functions as needed
            // [x] implement ELF verification for sanity checking
            // [x] implement TLS blocks for each PP
            // [x] implement intrinsic class
            // [x] implement system_rpt
            // [x] implement extension call back for bootstrapping
            // [x] implement extension call back wait for events
            // [x] implement extension call back for  vmexit
            // [x] implement creation of VMs
            // [x] implement creation of VPs
            // [x] implement creation of VPs
            // [x] implement creation of VPSs
            // [x] implement init VPS as root
            // [x] implement read/write VPS state
            // [x] implement continued execution with no exits
            // [x] implement vps_run / vmexit handler
            // [x] implement stopping the hypervisor
            // [x] implement fast fail for extension failing before vmrun
            // [x] implement fast fail for extension failing after vmrun
            // [x] implement fast fail for extension not calling bf_vps_run_op
            // [x] implement fast fail callback for extensions
            // [x] implement __stack_chk_fail
            // [x] implement dump_cpu_state for exception handler
            // [x] implement per-PP extension stacks
            // [x] implement multicore
            // [x] implement removal of extra IDs in syscall interface
            // [x] implement active VM
            // [x] implement active VP
            // [x] implement active VPS
            // [x] implement nmi support during demote
            // [x] implement per-PP extension TLS blocks
            // [x] implement intrinsics syscalls
            // [x] implement filtering of GPs for invalid MSR read/write
            // [x] implement nmi ESR with an rex64.IRET in the loader
            // [x] implement Intel support
            // [x] implement nmi support during microkernel execution for Intel
            // [x] implement version information using main() args.
            // [x] implement fs:xxx for extensions for register/exit data.
            // [x] implement run with an error code
            // [x] implement simplify the example as much as possible
            // [x] implement error on VMX instructions on Intel
            // [x] implement error on SVM instructions on AMD
            // [ ] implement fix for vmexit first crash (vmxoff and check state)
            // [x] implement fix for 128 cores on Windows
            // [x] implement alloc page
            // [ ] implement free page
            // [x] implement virt_to_phys
            // [ ] implement make ack
            // [ ] implement debugging mutex/transaction support
            // [x] implement Windows support
            // [ ] implement UEFI support
            // [ ] implement huge_pool
            // [ ] implement huge
            // [ ] implement alloc physically contiguous page
            // [ ] implement free physically contiguous page
            // [ ] implement per-VM direct maps
            // [ ] implement reduce the size of the TLS block
            // [ ] implement optimizations for release builds
            // [ ] implement dump functions for all types
            // [ ] implement all debug ops
            // [ ] implement some basic unit tests
            // [ ] implement some basic syscall tests

            // [ ] implement configuration validation
            // [ ] implement lock down which MSRs can be read/written
            // [ ] implement reproduceable builds
            // [ ] implement complete unit tests
            // [ ] implement complete syscall tests
            // [ ] implement heap support
            // [ ] implement IPC support
            // [ ] implement nmi support during promote
            // [ ] implement remaining todos
            // [ ] implement c extension example
            // [ ] implement mitigations for transient execution vulnerabilities

            // NMI Notes:
            // - On AMD, they are disabled, so we should never see them.
            // - On Intel, we cannot disable them. We can, however, generate
            //   an NMI VMExit. If an NMI fires while we are trying to start
            //   and the attempt to start fails, you might have to reboot as
            //   the NMI would be dropped, and we will warn the user. If an
            //   NMI fires at any other time, we make a note of it in the
            //   TLS block. Once we are in the "transition" portion for a
            //   VMResume, we will make note of that in the TLS block, and
            //   then we will check to see if an NMI was caught. If it was,
            //   we will then execute an int 2, which will force the NMI
            //   handler to execute. When the NMI handler executes, and it
            //   knows that we are in the "transition" portion of the
            //   code, it will always set the NMI window in whatever VMCS has
            //   been loaded, which will generate a VMExit that the extension
            //   will have to handle.
            //
        }
    };
}

#endif
