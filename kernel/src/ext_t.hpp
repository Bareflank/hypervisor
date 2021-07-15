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

#ifndef EXT_T_HPP
#define EXT_T_HPP

#include <alloc_huge_t.hpp>
#include <alloc_page_t.hpp>
#include <allocate_tags.hpp>
#include <bf_constants.hpp>
#include <bfelf/elf64_ehdr_t.hpp>
#include <bfelf/elf64_phdr_t.hpp>
#include <call_ext.hpp>
#include <ext_tcb_t.hpp>
#include <huge_pool_t.hpp>
#include <intrinsic_t.hpp>
#include <map_page_flags.hpp>
#include <mk_args_t.hpp>
#include <page_aligned_bytes_t.hpp>
#include <page_pool_t.hpp>
#include <page_t.hpp>
#include <root_page_table_t.hpp>
#include <start_vmm_args_t.hpp>
#include <tls_t.hpp>

#include <bsl/array.hpp>
#include <bsl/discard.hpp>
#include <bsl/finally.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>
#include <bsl/unlikely_assert.hpp>

/// TODO:
/// - Add support for multiple extensions. For this to work, we will need
///   support for PCID and the global flag should be turned off. This will
///   ensure that swaps to another extension (which require a CR3 change),
///   will not destroy performance. To ensure the hypervisor can support
///   systems without PCID, projects that use more than one extension like
///   MicroV should compile the additional extensions into both the main
///   extension, and the additional ones. On systems that don't have PCID,
///   it would call itself. Systems with PCID would call through IPC. You
///   could then have compile/runtime flags for forcing one path over the
///   other in situations where performace or security take precedence.
/// - Since the microkernel doesn't have a timer, the only way another
///   extension will execute is from some sort of IPC interface where an
///   extension calls into another extension to perform an action and then
///   returns a result. The best way to handle this would be to use an
///   instruction sequence similar to a VMCall and VMExit. The extension
///   would execute bf_ipc_op_call, which could take at most 6 arguments
///   that match the SysV calling conventions. The additional extension
///   would execute and then return using bf_ipc_op_return. There would
///   need to be some logic in the syscall code to make sure that this
///   return function was used properly (meaning you cannot return unless
///   you have been called, and you cannot run if you have been called).
///   From there, all that is finally needed is some way to share memory.
///   There are two options here. Shared memory, or a memcpy ABI. IMO, we
///   should use a memcpy ABI as shared memory really complicates things.
///   If shared memory is used, we should make sure, that like freeing a
///   page, unmapping shared memory is optional, meaning the microkernel
///   is nor required to honor the request.
/// - The TLS block that we use for the general purpose registers will need
///   to be shared as it is currently a problem. This way, a swap to another
///   extension only has to update the extension ID in that block, and then
///   swap CR3. The best way to handle this would be to have the extension
///   pool can allocate the shared portion of the TLS blocks for all of the
///   online PPs and then give this page to each extension as it initializes.
///   Then all we have to do is make sure that there is no state in there that
///   would be a problem for the extensions to share, which right now is just
///   the extension ID. If additional state is added to the ABI that is a
///   problem, we will either have to copy the entire block on each swap,
///   or make add a second page to the ABI, one that is shared, and one that
///   is not.

namespace mk
{
    /// @class mk::ext_t
    ///
    /// <!-- description -->
    ///   @brief Defines an extension WRT to the microkernel. Whenever an
    ///     executes, it must go through this class to do so. This class
    ///     also maintains all of the resources given to an extension, as
    ///     well as the extension's memory map, ELF file, stack, TLS blocks,
    ///     and all of it's memory map functions.
    ///
    class ext_t final
    {
        /// @brief stores true if start() has been executed
        bool m_started{};
        /// @brief stores the ID associated with this ext_t
        bsl::safe_uint16 m_id{bsl::safe_uint16::failure()};

        /// @brief stores the main rpt
        root_page_table_t m_main_rpt{};
        /// @brief stores the direct map rpts
        bsl::array<root_page_table_t, HYPERVISOR_MAX_VMS.get()> m_direct_map_rpts{};
        /// @brief stores the main IP registered by the extension
        bsl::safe_uintmax m_entry_ip{bsl::safe_uintmax::failure()};
        /// @brief stores the bootstrap IP registered by the extension
        bsl::safe_uintmax m_bootstrap_ip{bsl::safe_uintmax::failure()};
        /// @brief stores the vmexit IP registered by the extension
        bsl::safe_uintmax m_vmexit_ip{bsl::safe_uintmax::failure()};
        /// @brief stores the fail IP registered by the extension
        bsl::safe_uintmax m_fail_ip{bsl::safe_uintmax::failure()};
        /// @brief stores the extension's handle
        bsl::safe_uintmax m_handle{bsl::safe_uintmax::failure()};
        /// @brief stores the extension's heap cursor
        bsl::safe_uintmax m_heap_virt{HYPERVISOR_EXT_HEAP_POOL_ADDR};

        /// <!-- description -->
        ///   @brief Returns the program header table
        ///
        /// <!-- inputs/outputs -->
        ///   @param file the ELF file to get the program header table from
        ///   @return Returns the program header table
        ///
        [[nodiscard]] static constexpr auto
        get_phdrtab(bfelf::elf64_ehdr_t const *const file) noexcept
            -> bsl::span<bfelf::elf64_phdr_t const>
        {
            return {file->e_phdr, bsl::to_umax(file->e_phnum)};
        }

        /// <!-- description -->
        ///   @brief Returns "size" as a "page_aligned_bytes_t"
        ///
        /// <!-- inputs/outputs -->
        ///   @param size the number of bytes to convert
        ///   @return Returns "size" as a "page_aligned_bytes_t"
        ///
        [[nodiscard]] static constexpr auto
        size_to_page_aligned_bytes(bsl::safe_uintmax const &size) noexcept -> page_aligned_bytes_t
        {
            constexpr auto one{1_umax};
            constexpr auto zero{0_umax};

            if (bsl::unlikely(size.is_zero_or_invalid())) {
                bsl::error() << "invalid size "    // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return {bsl::safe_uintmax::failure(), bsl::safe_uintmax::failure()};
            }

            if ((size % HYPERVISOR_PAGE_SIZE) != zero) {
                auto const pages{(size >> HYPERVISOR_PAGE_SHIFT) + one};
                return {pages * HYPERVISOR_PAGE_SIZE, pages};
            }

            auto const pages{(size >> HYPERVISOR_PAGE_SHIFT)};
            return {pages * HYPERVISOR_PAGE_SIZE, pages};
        }

        /// <!-- description -->
        ///   @brief Checks whether or not a given ELF file is in a format that
        ///     this ELF loader can handle.
        ///
        /// <!-- inputs/outputs -->
        ///   @param file a pointer to the elf file
        ///   @return Returns 0 on success or an error code on failure.
        ///
        [[nodiscard]] static constexpr auto
        validate_elf64_ehdr(bfelf::elf64_ehdr_t const *const file) noexcept -> bsl::errc_type
        {
            if (nullptr == file) {
                bsl::error() << "invalid file\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (*file->e_ident.at_if(bfelf::EI_MAG0) != bfelf::ELFMAG0) {
                bsl::error() << "invalid ELF magic number\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (*file->e_ident.at_if(bfelf::EI_MAG1) != bfelf::ELFMAG1) {
                bsl::error() << "invalid ELF magic number\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (*file->e_ident.at_if(bfelf::EI_MAG2) != bfelf::ELFMAG2) {
                bsl::error() << "invalid ELF magic number\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (*file->e_ident.at_if(bfelf::EI_MAG3) != bfelf::ELFMAG3) {
                bsl::error() << "invalid ELF magic number\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (*file->e_ident.at_if(bfelf::EI_CLASS) != bfelf::ELFCLASS64) {
                bsl::error() << "invalid ELF class\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (*file->e_ident.at_if(bfelf::EI_OSABI) != bfelf::ELFOSABI_SYSV) {
                bsl::error() << "invalid ELF OSABI\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (file->e_type != bfelf::ET_EXEC) {
                bsl::error() << "invalid ELF type\n" << bsl::here();
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Validates the provided pt_load segment.
        ///
        /// <!-- inputs/outputs -->
        ///   @param phdr the pt_load segment to validate
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        validate_pt_load(bfelf::elf64_phdr_t const *const phdr) noexcept -> bsl::errc_type
        {
            constexpr auto lower{HYPERVISOR_EXT_CODE_ADDR};
            constexpr auto upper{HYPERVISOR_EXT_CODE_ADDR + HYPERVISOR_EXT_CODE_SIZE};

            auto const addr{bsl::to_umax(phdr->p_vaddr)};
            auto const size{bsl::to_umax(phdr->p_memsz)};

            if ((bsl::to_u32(phdr->p_flags) & bfelf::PF_W).is_pos()) {
                if (bsl::unlikely((bsl::to_u32(phdr->p_flags) & bfelf::PF_X).is_pos())) {
                    bsl::error() << "ELF code segment flags not supported\n" << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            if (bsl::unlikely(addr < lower)) {
                bsl::error() << "ELF code segment not supported\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(addr + size > upper)) {
                bsl::error() << "ELF code segment not supported\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(phdr->p_align != HYPERVISOR_PAGE_SIZE)) {
                bsl::error() << "ELF code segment alignment not supported\n" << bsl::here();
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Validates the provided pt_gnu_stack segment.
        ///
        /// <!-- inputs/outputs -->
        ///   @param phdr the pt_gnu_stack segment to validate
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        validate_pt_gnu_stack(bfelf::elf64_phdr_t const *const phdr) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely((bsl::to_u32(phdr->p_flags) & bfelf::PF_X).is_pos())) {
                bsl::error() << "Executable stacks are not supported\n" << bsl::here();
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Validates the provided pt_tls segment.
        ///
        /// <!-- inputs/outputs -->
        ///   @param phdr the pt_tls segment to validate
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        validate_pt_tls(bfelf::elf64_phdr_t const *const phdr) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely((bsl::to_u32(phdr->p_flags) & bfelf::PF_X).is_pos())) {
                bsl::error() << "Executable TLS segment are not supported\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(bsl::to_umax(phdr->p_memsz) > HYPERVISOR_PAGE_SIZE)) {
                bsl::error() << "ELF TLS segment memsz not supported\n" << bsl::here();
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Validates the provided ELF file.
        ///
        /// <!-- inputs/outputs -->
        ///   @param elf_file the elf file to validate
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        validate(loader::ext_elf_file_t const *const elf_file) noexcept -> bsl::errc_type
        {
            if constexpr (BSL_RELEASE_MODE) {
                return bsl::errc_success;
            }

            if (bsl::unlikely(!validate_elf64_ehdr(elf_file))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            /// TODO:
            /// - Add support for GNU RELOC segments so that we can set
            ///   the RW permissions properly
            ///

            bool mut_found_pt_load{};
            bool mut_found_pt_gnu_stack{};

            for (auto const elem : get_phdrtab(elf_file)) {
                switch (elem.data->p_type) {
                    case bfelf::PT_LOAD.get(): {
                        mut_found_pt_load = true;
                        if (bsl::unlikely(!validate_pt_load(elem.data))) {
                            bsl::print<bsl::V>() << bsl::here();
                            return bsl::errc_failure;
                        }
                        break;
                    }

                    case bfelf::PT_GNU_STACK.get(): {
                        mut_found_pt_gnu_stack = true;
                        if (bsl::unlikely(!validate_pt_gnu_stack(elem.data))) {
                            bsl::print<bsl::V>() << bsl::here();
                            return bsl::errc_failure;
                        }
                        break;
                    }

                    case bfelf::PT_TLS.get(): {
                        if (bsl::unlikely(!validate_pt_tls(elem.data))) {
                            bsl::print<bsl::V>() << bsl::here();
                            return bsl::errc_failure;
                        }
                        break;
                    }

                    default: {
                        break;
                    }
                }
            }

            if (bsl::unlikely(!mut_found_pt_load)) {
                bsl::error() << "PT_LOAD segments missing from ELF file\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!mut_found_pt_gnu_stack)) {
                bsl::error() << "PT_GNU_STACK segment missing from ELF file\n" << bsl::here();
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Allocate the a page of RW or RW memory for the segment
        ///     being loaded.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param mut_rpt the root page table to add too
        ///   @param phdr the pt_load segment to add
        ///   @param offset the offset in the segment being allocated
        ///   @return Returns a pointer to the newly allocated page, or a
        ///     nullptr on failure.
        ///
        [[nodiscard]] static constexpr auto
        allocate_page_for_add_segment(
            tls_t &mut_tls,
            page_pool_t &mut_page_pool,
            root_page_table_t &mut_rpt,
            bfelf::elf64_phdr_t const *const phdr,
            bsl::safe_uintmax const &offset) noexcept -> page_t *
        {
            if ((phdr->p_flags & bfelf::PF_X).is_pos()) {
                return mut_rpt.allocate_page_rx<page_t>(
                    mut_tls, mut_page_pool, phdr->p_vaddr + offset, MAP_PAGE_AUTO_RELEASE_ELF);
            }

            return mut_rpt.allocate_page_rw<page_t>(
                mut_tls, mut_page_pool, phdr->p_vaddr + offset, MAP_PAGE_AUTO_RELEASE_ELF);
        }

        /// <!-- description -->
        ///   @brief Adds all of the program segments given an ELF file to
        ///     the provided root page table.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param mut_rpt the root page table to add too
        ///   @param phdr the pt_load segment to add
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        add_segment(
            tls_t &mut_tls,
            page_pool_t &mut_page_pool,
            root_page_table_t &mut_rpt,
            bfelf::elf64_phdr_t const *const phdr) noexcept -> bsl::errc_type
        {
            bsl::span const segment{phdr->p_offset, bsl::to_umax(phdr->p_filesz)};
            for (bsl::safe_uintmax mut_i{}; mut_i < phdr->p_memsz; mut_i += HYPERVISOR_PAGE_SIZE) {
                auto *const pmut_page{
                    allocate_page_for_add_segment(mut_tls, mut_page_pool, mut_rpt, phdr, mut_i)};
                if (bsl::unlikely(nullptr == pmut_page)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                auto const src{segment.subspan(mut_i, HYPERVISOR_PAGE_SIZE)};
                if (src.empty()) {
                    continue;
                }

                bsl::builtin_memcpy(pmut_page->data.data(), src.data(), src.size());
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds all of the program segments given an ELF file to
        ///     the provided root page table.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param mut_rpt the root page table to add too
        ///   @param elf_file the ELF file for this ext_t
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        add_segments(
            tls_t &mut_tls,
            page_pool_t &mut_page_pool,
            root_page_table_t &mut_rpt,
            loader::ext_elf_file_t const *const elf_file) noexcept -> bsl::errc_type
        {
            for (auto const elem : get_phdrtab(elf_file)) {
                if (bfelf::PT_LOAD != elem.data->p_type) {
                    continue;
                }

                auto const ret{add_segment(mut_tls, mut_page_pool, mut_rpt, elem.data)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds an exteneion's stack for a specific PP to the
        ///     provided root page table at the provided address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param mut_rpt the root page table to add too
        ///   @param addr the address of where to put the stack
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        add_stack(
            tls_t &mut_tls,
            page_pool_t &mut_page_pool,
            root_page_table_t &mut_rpt,
            bsl::safe_uintmax const &addr) noexcept -> bsl::errc_type
        {
            constexpr auto size{HYPERVISOR_EXT_STACK_SIZE};
            for (bsl::safe_uintmax mut_i{}; mut_i < size; mut_i += HYPERVISOR_PAGE_SIZE) {
                auto const *const page{mut_rpt.allocate_page_rw<page_t>(
                    mut_tls, mut_page_pool, addr + mut_i, MAP_PAGE_AUTO_RELEASE_STACK)};
                if (bsl::unlikely(nullptr == page)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds the exteneion's stacks to the provided
        ///     root page table.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param mut_rpt the root page table to add too
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        add_stacks(tls_t &mut_tls, page_pool_t &mut_page_pool, root_page_table_t &mut_rpt) noexcept
            -> bsl::errc_type
        {
            for (bsl::safe_uintmax mut_i{}; mut_i < bsl::to_umax(mut_tls.online_pps); ++mut_i) {
                auto const offs{(HYPERVISOR_EXT_STACK_SIZE + HYPERVISOR_PAGE_SIZE) * mut_i};
                auto const addr{(HYPERVISOR_EXT_STACK_ADDR + offs)};

                auto const ret{this->add_stack(mut_tls, mut_page_pool, mut_rpt, addr)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds an exteneion's TLS (has nothing to do with the
        ///     microkernel's TLS). Remember that each extension has two pages
        ///     of TLS block stuff. One page for TLS data, which is anything
        ///     that an extension defines with thread_local and will show up
        ///     in the ELF file as a program segment, and one page for the
        ///     Thread Control Block (TCB) which stores a pointer that is
        ///     needed by thread_local as well as TLS data that is defined by
        ///     the ABI like the general purpose registers. This adds the TLS
        ///     data in that first page an is only called when an extension
        ///     actually uses thread_local. From a memory layout point of view,
        ///     the TLS data comes first (right justified), then the "tp" which
        ///     is the value written to FS and is a self pointer, and then the
        ///     TCB data, which define in the ABI.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param mut_rpt the root page table to add too
        ///   @param addr the address of the TLS data
        ///   @param phdr the TLS segment to copy TLS data from
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        add_tls(
            tls_t &mut_tls,
            page_pool_t &mut_page_pool,
            root_page_table_t &mut_rpt,
            bsl::safe_uintmax const &addr,
            bfelf::elf64_phdr_t const *const phdr) noexcept -> bsl::errc_type
        {
            auto *const pmut_page{mut_rpt.allocate_page_rw<page_t>(
                mut_tls, mut_page_pool, addr, MAP_PAGE_AUTO_RELEASE_TLS)};
            if (bsl::unlikely(nullptr == pmut_page)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            /// NOTE:
            /// - The dst_idx is needed because the TLS data is in a sense,
            ///   right justified. Meaning, we allocate a full page, but if
            ///   the extension only uses 100 bytes, the data starts at the
            ///   last 100 bytes of the page.
            /// - The dst_idx does not need to be checked because the
            ///   validation code checks for this already, and the memcpy
            ///   function will not attempt to use an invalid size as a
            ///   nie backup.
            ///

            bsl::span const src{phdr->p_offset, bsl::to_umax(phdr->p_filesz)};
            auto const dst_idx{HYPERVISOR_PAGE_SIZE - bsl::to_umax(phdr->p_memsz)};
            bsl::builtin_memcpy(pmut_page->data.at_if(dst_idx), src.data(), src.size());

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds an exteneion's TLS block for a specific PP to the
        ///     provided root page table at the provided address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param mut_rpt the root page table to add too
        ///   @param addr the address of the TCB portion of the TLS block
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        add_tcb(
            tls_t &mut_tls,
            page_pool_t &mut_page_pool,
            root_page_table_t &mut_rpt,
            bsl::safe_uintmax const &addr) noexcept -> bsl::errc_type
        {
            auto *const pmut_page{mut_rpt.allocate_page_rw<ext_tcb_t>(
                mut_tls, mut_page_pool, addr, MAP_PAGE_AUTO_RELEASE_TCB)};
            if (bsl::unlikely(nullptr == pmut_page)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            pmut_page->tp = addr.get();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds the exteneion's TLS block to the provided
        ///     root page table.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param mut_rpt the root page table to add too
        ///   @param elf_file the ELF file that contains the TLS info
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        add_tls_blocks(
            tls_t &mut_tls,
            page_pool_t &mut_page_pool,
            root_page_table_t &mut_rpt,
            loader::ext_elf_file_t const *const elf_file) noexcept -> bsl::errc_type
        {
            for (bsl::safe_uintmax mut_i{}; mut_i < bsl::to_umax(mut_tls.online_pps); ++mut_i) {
                auto const offs{(HYPERVISOR_EXT_TLS_SIZE + HYPERVISOR_PAGE_SIZE) * mut_i};
                auto const addr{(HYPERVISOR_EXT_TLS_ADDR + offs)};

                auto const ret{
                    this->add_tcb(mut_tls, mut_page_pool, mut_rpt, addr + HYPERVISOR_PAGE_SIZE)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }

            bfelf::elf64_phdr_t const *mut_phdr{};
            for (auto const elem : get_phdrtab(elf_file)) {
                if (bfelf::PT_TLS == elem.data->p_type) {
                    mut_phdr = elem.data;
                    break;
                }

                bsl::touch();
            }

            if (nullptr == mut_phdr) {
                return bsl::errc_success;
            }

            for (bsl::safe_uintmax mut_i{}; mut_i < bsl::to_umax(mut_tls.online_pps); ++mut_i) {
                auto const offs{(HYPERVISOR_EXT_TLS_SIZE + HYPERVISOR_PAGE_SIZE) * mut_i};
                auto const addr{(HYPERVISOR_EXT_TLS_ADDR + offs)};

                auto const ret{this->add_tls(mut_tls, mut_page_pool, mut_rpt, addr, mut_phdr)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Initializes a root page table to support the execution
        ///     of this extension.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param mut_rpt the root page table to initialize
        ///   @param system_rpt the system root page table to initialize with
        ///   @param elf_file the ELF file that contains the segment and TLS
        ///      info need to initialize the provided rpt
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize_rpt(
            tls_t &mut_tls,
            page_pool_t &mut_page_pool,
            root_page_table_t &mut_rpt,
            root_page_table_t const &system_rpt,
            loader::ext_elf_file_t const *const elf_file) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely(!mut_rpt.initialize(mut_tls, mut_page_pool))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            bsl::finally mut_release_on_error{
                [&mut_tls, &mut_rpt, &mut_page_pool]() noexcept -> void {
                    mut_rpt.release(mut_tls, mut_page_pool);
                }};

            if (bsl::unlikely(!mut_rpt.add_tables(mut_tls, system_rpt))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->add_segments(mut_tls, mut_page_pool, mut_rpt, elf_file))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->add_stacks(mut_tls, mut_page_pool, mut_rpt))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->add_tls_blocks(mut_tls, mut_page_pool, mut_rpt, elf_file))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            mut_release_on_error.ignore();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Initializes a direct map root page table to support the
        ///     execution of this extension (with the inclusion of a direct
        ///     map).
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param mut_rpt the root page table to initialize
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize_direct_map_rpt(
            tls_t &mut_tls, page_pool_t &mut_page_pool, root_page_table_t &mut_rpt) noexcept
            -> bsl::errc_type
        {
            if (bsl::unlikely(!mut_rpt.initialize(mut_tls, mut_page_pool))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            bsl::finally mut_release_on_error{
                [&mut_tls, &mut_rpt, &mut_page_pool]() noexcept -> void {
                    mut_rpt.release(mut_tls, mut_page_pool);
                }};

            if (bsl::unlikely(!mut_rpt.add_tables(mut_tls, m_main_rpt))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            mut_release_on_error.ignore();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief There are three different types of memory that an
        ///     extension can allocate: page, huge and heap. The page and
        ///     huge memory are allocated into the direct map, which provides
        ///     the extension with the ability to do virtual address to
        ///     physical address conversions. The heap is different in that it
        ///     must be virtual contiguous, which means that a virtual address
        ///     to physical address conversion would require a page walk, and
        ///     we really want to discourage that.
        ///
        ///     There are also two different ways to map memory into an
        ///     extension. You can map the memory in using m_main_rpt, which
        ///     is the RPT that is shared between all VMs. Meaning, no matter
        ///     which VM is executing, the extension will always be able to
        ///     use memory mapped into this RPT. The second RPT is the direct
        ///     map RPTs. Extensions ALWAYS uses a direct map RPT to execute
        ///     By default, VM 0 is used unless the extension runs another VM.
        ///
        ///     To map in page, huge or heap memory, we have two options: map
        ///     the memory into m_main_rpt or m_direct_map_rpts. ALL memory
        ///     that is mapped into the direct map must be mapped using the
        ///     m_direct_map_rpts. The reason is, the PML4 entries associated
        ///     with the direct map CANNOT be mapped into the m_main_rpt.
        ///     Doing so would cause the extension to be able to see most, if
        ///     not all of the direct mapped memory that has nothing to do
        ///     with the page and huge memory allocations. The problem is
        ///     if a page is allocated into a direct map, when a VM is deleted,
        ///     what do we do? How do we know when to actually release the
        ///     allocated memory back to the microkernel's page/huge pools.
        ///
        ///     To handle this issue, we map all memory that is allocated
        ///     using the page/huge memory into the direct map for VM 0.
        ///     The extension is not allowed to destroy VM 0. In addition,
        ///     since this memory is allocated into VM 0, when an extension
        ///     attempts to access this memory from a different VM, it will
        ///     generate a page fault. This memory address is however a direct
        ///     map address, and as such, the extension will map in this
        ///     memory the same way it would for any other direct map address,
        ///     with auto_release turned off. When the extension is finally
        ///     removed, we remove the direct maps, including VM 0, and the
        ///     memory is properly freed.
        ///
        ///     All we have left to do is deal with heap memory. We cannot
        ///     allocate this memory into the direct map because it needs
        ///     to be virtually contiguous. This means that we HAVE to map
        ///     this memory into m_main_rpt. The problem is, this RPT is
        ///     created when the extension is initialized, and then it is
        ///     only used when you initialize a direct map. But what if an
        ///     extension allocates heap memory after the direct map is
        ///     initialized? That's where this function comes into play. It's
        ///     job is to make sure that we add any PML4 entires from
        ///     m_main_rpt that may have been added back into the direct
        ///     maps that are active so that any changes to m_main_rpt are
        ///     properly accounted for.
        ///
        ///     Just as a reminder, the way that these RPTs are layed out,
        ///     is each PML4 is dedicated to a specific purpose, and these
        ///     cannot be shared. For example, some PML4s are dedicated to
        ///     the microkernel's memory, some for the extension, the stacks
        ///     the TLS blocks, etc... You cannot mix and match.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        update_direct_map_rpts(tls_t &mut_tls) noexcept -> bsl::errc_type
        {
            for (auto const rpt : m_direct_map_rpts) {
                if (!rpt.data->is_initialized()) {
                    continue;
                }

                if (bsl::unlikely(!rpt.data->add_tables(mut_tls, m_main_rpt))) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Executes the extension given an instruction pointer to
        ///     execute the extension at, a stack pointer to execute the
        ///     extension with, and a root page table defining the memory
        ///     layout to execute the extension with.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsic_t to use
        ///   @param ip the instruction pointer defining where in the
        ///     extension to start execution at.
        ///   @param arg0 the first argument to pass the extension
        ///   @param arg1 the second argument to pass the extension
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        execute(
            tls_t &mut_tls,
            intrinsic_t &mut_intrinsic,
            bsl::safe_uintmax const &ip,
            bsl::safe_uintmax const &arg0 = {},
            bsl::safe_uintmax const &arg1 = {}) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "ext_t not initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(!ip)) {
                bsl::error() << "invalid instruction pointer\n" << bsl::here();
                return bsl::errc_failure;
            }

            auto *const pmut_rpt{m_direct_map_rpts.at_if(bsl::to_umax(mut_tls.active_vmid))};
            if (bsl::unlikely_assert(nullptr == pmut_rpt)) {
                bsl::error() << "invalid active_vmid "           // --
                             << bsl::hex(mut_tls.active_vmid)    // --
                             << bsl::endl                        // --
                             << bsl::here();                     // --

                return bsl::errc_failure;
            }

            if (mut_tls.active_rpt != pmut_rpt) {
                if (bsl::unlikely_assert(!pmut_rpt->activate(mut_tls, mut_intrinsic))) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                mut_tls.active_rpt = pmut_rpt;
            }
            else {
                bsl::touch();
            }

            if (mut_tls.ext != this) {
                mut_tls.ext = this;
                mut_tls.active_extid = m_id.get();
            }
            else {
                bsl::touch();
            }

            bsl::exit_code const ret{call_ext(ip.get(), mut_tls.sp, arg0.get(), arg1.get())};
            if (bsl::unlikely(bsl::exit_success != ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

    public:
        /// <!-- description -->
        ///   @brief Initializes this ext_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param i the ID for this ext_t
        ///   @param elf_file the ELF file for this ext_t
        ///   @param system_rpt the system RPT provided by the loader
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(
            tls_t &mut_tls,
            page_pool_t &mut_page_pool,
            bsl::safe_uint16 const &i,
            loader::ext_elf_file_t const *const elf_file,
            root_page_table_t const &system_rpt) noexcept -> bsl::errc_type
        {
            bsl::errc_type mut_ret{};

            if (bsl::unlikely_assert(m_id)) {
                bsl::error() << "ext_t already initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            bsl::finally mut_release_on_error{[this, &mut_tls, &mut_page_pool]() noexcept -> void {
                this->release(mut_tls, mut_page_pool);
            }};

            if (bsl::unlikely_assert(!i)) {
                bsl::error() << "invalid id\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(nullptr == elf_file)) {
                bsl::error() << "invalid elf_file\n" << bsl::here();
                return bsl::errc_failure;
            }

            mut_ret = validate(elf_file);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret =
                this->initialize_rpt(mut_tls, mut_page_pool, m_main_rpt, system_rpt, elf_file);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            m_entry_ip = elf_file->e_entry;
            m_id = i;

            mut_release_on_error.ignore();
            return mut_ret;
        }

        /// <!-- description -->
        ///   @brief Release the ext_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///
        constexpr void
        release(tls_t &mut_tls, page_pool_t &mut_page_pool) noexcept
        {
            m_heap_virt = {HYPERVISOR_EXT_HEAP_POOL_ADDR};
            m_handle = bsl::safe_uintmax::failure();
            m_fail_ip = bsl::safe_uintmax::failure();
            m_vmexit_ip = bsl::safe_uintmax::failure();
            m_bootstrap_ip = bsl::safe_uintmax::failure();
            m_entry_ip = bsl::safe_uintmax::failure();

            for (auto const rpt : m_direct_map_rpts) {
                rpt.data->release(mut_tls, mut_page_pool);
            }

            m_main_rpt.release(mut_tls, mut_page_pool);

            m_id = bsl::safe_uint16::failure();
            m_started = {};
        }

        /// <!-- description -->
        ///   @brief Returns the ID of this ext_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of this ext_t
        ///
        [[nodiscard]] constexpr auto
        id() const noexcept -> bsl::safe_uint16 const &
        {
            return m_id;
        }

        /// <!-- description -->
        ///   @brief Returns the bootstrap IP for this extension.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the bootstrap IP for this extension.
        ///
        [[nodiscard]] constexpr auto
        bootstrap_ip() const noexcept -> bsl::safe_uintmax const &
        {
            return m_bootstrap_ip;
        }

        /// <!-- description -->
        ///   @brief Sets the bootstrap IP for this extension. This should
        ///     be called by the syscall dispatcher as the result of a
        ///     syscall from the extension defining what IP the extension
        ///     would like to use for bootstrapping.
        ///
        /// <!-- inputs/outputs -->
        ///   @param ip the bootstrap IP to use
        ///
        constexpr void
        set_bootstrap_ip(bsl::safe_uintmax const &ip) noexcept
        {
            m_bootstrap_ip = ip;
        }

        /// <!-- description -->
        ///   @brief Returns the VMExit IP for this extension.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the VMExit IP for this extension.
        ///
        [[nodiscard]] constexpr auto
        vmexit_ip() const noexcept -> bsl::safe_uintmax const &
        {
            return m_vmexit_ip;
        }

        /// <!-- description -->
        ///   @brief Sets the VMExit IP for this extension. This should
        ///     be called by the syscall dispatcher as the result of a
        ///     syscall from the extension defining what IP the extension
        ///     would like to use for VMExits.
        ///
        /// <!-- inputs/outputs -->
        ///   @param ip the VMExit IP to use
        ///
        constexpr void
        set_vmexit_ip(bsl::safe_uintmax const &ip) noexcept
        {
            m_vmexit_ip = ip;
        }

        /// <!-- description -->
        ///   @brief Returns the fast fail IP for this extension.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the fast fail IP for this extension.
        ///
        [[nodiscard]] constexpr auto
        fail_ip() const noexcept -> bsl::safe_uintmax const &
        {
            return m_fail_ip;
        }

        /// <!-- description -->
        ///   @brief Sets the fast fail IP for this extension. This should
        ///     be called by the syscall dispatcher as the result of a
        ///     syscall from the extension defining what IP the extension
        ///     would like to use for fail callbacks.
        ///
        /// <!-- inputs/outputs -->
        ///   @param ip the fail IP to use
        ///
        constexpr void
        set_fail_ip(bsl::safe_uintmax const &ip) noexcept
        {
            m_fail_ip = ip;
        }

        /// <!-- description -->
        ///   @brief Opens a handle and returns the resulting handle
        ///
        /// <!-- inputs/outputs -->
        ///   @return Opens a handle and returns the resulting handle
        ///
        [[nodiscard]] constexpr auto
        open_handle() noexcept -> bsl::safe_uintmax
        {
            if (bsl::unlikely(m_handle)) {
                bsl::error() << "handle already opened\n" << bsl::here();
                return bsl::safe_uintmax::failure();
            }

            constexpr auto offset{1_umax};
            m_handle = bsl::to_umax(this->id()) + offset;
            return m_handle;
        }

        /// <!-- description -->
        ///   @brief Closes a previously opened handle
        ///
        constexpr void
        close_handle() noexcept
        {
            m_handle = bsl::safe_uintmax::failure();
        }

        /// <!-- description -->
        ///   @brief Returns true if the extension's handle is open.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the extension's handle is open.
        ///
        [[nodiscard]] constexpr auto
        is_handle_open() const noexcept -> bool
        {
            return !!m_handle;
        }

        /// <!-- description -->
        ///   @brief Returns true if provided handle is valid
        ///
        /// <!-- inputs/outputs -->
        ///   @param handle the handle to verify
        ///   @return Returns true if provided handle is valid
        ///
        [[nodiscard]] constexpr auto
        is_handle_valid(bsl::safe_uintmax const &handle) const noexcept -> bool
        {
            return handle == m_handle;
        }

        /// <!-- description -->
        ///   @brief Returns true if the extension's main function has
        ///     completed it's execution.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the extension's main function has
        ///     completed it's execution.
        ///
        [[nodiscard]] constexpr auto
        is_started() const noexcept -> bool
        {
            return m_started;
        }

        /// <!-- description -->
        ///   @brief Allocates a page and maps it into the extension's
        ///     address space.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @return Returns a alloc_page_t containing the virtual address and
        ///     physical address of the page. If an error occurs, this
        ///     function will return an invalid virtual and physical address.
        ///
        [[nodiscard]] constexpr auto
        alloc_page(tls_t &mut_tls, page_pool_t &mut_page_pool) noexcept -> alloc_page_t
        {
            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "ext_t not initialized\n" << bsl::here();
                return {bsl::safe_uintmax::failure(), bsl::safe_uintmax::failure()};
            }

            auto const *const page{
                mut_page_pool.allocate<page_t>(mut_tls, ALLOCATE_TAG_BF_MEM_OP_ALLOC_PAGE)};
            if (bsl::unlikely(nullptr == page)) {
                bsl::print<bsl::V>() << bsl::here();
                return {bsl::safe_uintmax::failure(), bsl::safe_uintmax::failure()};
            }

            auto const page_phys{mut_page_pool.virt_to_phys(page)};
            if (bsl::unlikely_assert(!page_phys)) {
                bsl::print<bsl::V>() << bsl::here();
                return {bsl::safe_uintmax::failure(), bsl::safe_uintmax::failure()};
            }

            auto const page_virt{HYPERVISOR_EXT_PAGE_POOL_ADDR + page_phys};
            if (bsl::unlikely_assert(!page_virt)) {
                bsl::print<bsl::V>() << bsl::here();
                return {bsl::safe_uintmax::failure(), bsl::safe_uintmax::failure()};
            }

            /// NOTE:
            /// - See update_direct_map_rpts for more details on how this
            ///   works, but the TL;DR is, we map the page into VM 0's direct
            ///   map. VM 0 cannot be destroyed, so auto_release works as
            ///   expected here as destroying any other VM will not attempt
            ///   to free the page we are mapping here. The extension can
            ///   access this memory from any VM as this is direct map memory
            ///   so any attempt to access this memory when a VM is active
            ///   that is not #0 will result in a page fault, and the page
            ///   handler will direct map the address into that VM as it
            ///   would any other physical address.
            ///

            auto const ret{m_direct_map_rpts.front().map_page(
                mut_tls,
                mut_page_pool,
                page_virt,
                page_phys,
                MAP_PAGE_READ | MAP_PAGE_WRITE,
                MAP_PAGE_AUTO_RELEASE_ALLOC_PAGE)};

            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return {bsl::safe_uintmax::failure(), bsl::safe_uintmax::failure()};
            }

            return {page_virt, page_phys};
        }

        /// <!-- description -->
        ///   @brief Frees a page that was mapped it into the extension's
        ///     address space.
        ///
        /// <!-- inputs/outputs -->
        ///   @param page_virt the virtual address to free
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        free_page(bsl::safe_uintmax const &page_virt) noexcept -> bsl::errc_type
        {
            bsl::discard(page_virt);

            bsl::error() << "free_page is currently unsupported\n" << bsl::here();
            return bsl::errc_failure;
        }

        /// <!-- description -->
        ///   @brief Allocates a physically contiguous block of memory and maps
        ///     it into the extension's address space.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param mut_huge_pool the huge_pool_t to use
        ///   @param size the total number of bytes to allocate
        ///   @return Returns a huge_t containing the virtual address and
        ///     physical address of the memory block. If an error occurs, this
        ///     function will return an invalid virtual and physical address.
        ///
        [[nodiscard]] constexpr auto
        alloc_huge(
            tls_t &mut_tls,
            page_pool_t &mut_page_pool,
            huge_pool_t &mut_huge_pool,
            bsl::safe_uintmax const &size) noexcept -> alloc_huge_t
        {
            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "ext_t not initialized\n" << bsl::here();
                return {bsl::safe_uintmax::failure(), bsl::safe_uintmax::failure()};
            }

            auto const [bytes, pages]{size_to_page_aligned_bytes(size)};
            if (bsl::unlikely(!pages)) {
                bsl::print<bsl::V>() << bsl::here();
                return {bsl::safe_uintmax::failure(), bsl::safe_uintmax::failure()};
            }

            auto const huge{mut_huge_pool.allocate(mut_tls, bytes)};
            if (bsl::unlikely(!huge)) {
                bsl::print<bsl::V>() << bsl::here();
                return {bsl::safe_uintmax::failure(), bsl::safe_uintmax::failure()};
            }

            auto const huge_phys{mut_huge_pool.virt_to_phys(huge.data())};
            if (bsl::unlikely_assert(!huge_phys)) {
                bsl::print<bsl::V>() << bsl::here();
                return {bsl::safe_uintmax::failure(), bsl::safe_uintmax::failure()};
            }

            auto const huge_virt{HYPERVISOR_EXT_PAGE_POOL_ADDR + huge_phys};
            if (bsl::unlikely_assert(!huge_virt)) {
                bsl::print<bsl::V>() << bsl::here();
                return {bsl::safe_uintmax::failure(), bsl::safe_uintmax::failure()};
            }

            /// NOTE:
            /// - See update_direct_map_rpts for more details on how this
            ///   works, but the TL;DR is, we map the page into VM 0's direct
            ///   map. VM 0 cannot be destroyed, so auto_release works as
            ///   expected here as destroying any other VM will not attempt
            ///   to free the page we are mapping here. The extension can
            ///   access this memory from any VM as this is direct map memory
            ///   so any attempt to access this memory when a VM is active
            ///   that is not #0 will result in a page fault, and the page
            ///   handler will direct map the address into that VM as it
            ///   would any other physical address.
            ///

            for (bsl::safe_uintmax mut_i{}; mut_i < pages; ++mut_i) {
                auto const ret{m_direct_map_rpts.front().map_page(
                    mut_tls,
                    mut_page_pool,
                    huge_virt + mut_i,
                    huge_phys + mut_i,
                    MAP_PAGE_READ | MAP_PAGE_WRITE,
                    MAP_PAGE_NO_AUTO_RELEASE)};

                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return {bsl::safe_uintmax::failure(), bsl::safe_uintmax::failure()};
                }

                bsl::touch();
            }

            return {huge_virt, huge_phys};
        }

        /// <!-- description -->
        ///   @brief Frees a physically contiguous block of memory that was
        ///     mapped it into the extension's address space.
        ///
        /// <!-- inputs/outputs -->
        ///   @param huge_virt the virtual address to free
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        free_huge(bsl::safe_uintmax const &huge_virt) noexcept -> bsl::errc_type
        {
            bsl::discard(huge_virt);

            bsl::error() << "free_huge is currently unsupported\n" << bsl::here();
            return bsl::errc_failure;
        }

        /// <!-- description -->
        ///   @brief Allocates heap memory and maps it into the extension's
        ///     address space.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param size the total number of bytes to allocate and add
        ///     to the heap.
        ///   @return On success, alloc_heap returns the previous address
        ///     virtual address of the heap. If an error occurs, this
        ///     function returns bsl::safe_uintmax::failure().
        ///
        [[nodiscard]] constexpr auto
        alloc_heap(
            tls_t &mut_tls, page_pool_t &mut_page_pool, bsl::safe_uintmax const &size) noexcept
            -> bsl::safe_uintmax
        {
            auto const old_heap_virt{m_heap_virt};
            constexpr auto pool_addr{HYPERVISOR_EXT_HEAP_POOL_ADDR};
            constexpr auto pool_size{HYPERVISOR_EXT_HEAP_POOL_SIZE};

            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "ext_t not initialized\n" << bsl::here();
                return bsl::safe_uintmax::failure();
            }

            auto const [bytes, pages]{size_to_page_aligned_bytes(size)};
            if (bsl::unlikely(!pages)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uintmax::failure();
            }

            if (bsl::unlikely((m_heap_virt + bytes) > (pool_addr + pool_size))) {
                bsl::error() << "the extension's heap pool is out of memory"    // --
                             << bsl::endl                                       // --
                             << bsl::here();                                    // --

                return bsl::safe_uintmax::failure();
            }

            for (bsl::safe_uintmax mut_i{}; mut_i < pages; ++mut_i) {
                auto const *const page{
                    mut_page_pool.allocate<page_t>(mut_tls, ALLOCATE_TAG_BF_MEM_OP_ALLOC_HEAP)};
                if (bsl::unlikely(nullptr == page)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::safe_uintmax::failure();
                }

                auto const page_phys{mut_page_pool.virt_to_phys(page)};
                if (bsl::unlikely_assert(!page_phys)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::safe_uintmax::failure();
                }

                auto const ret{m_main_rpt.map_page(
                    mut_tls,
                    mut_page_pool,
                    m_heap_virt,
                    page_phys,
                    MAP_PAGE_READ | MAP_PAGE_WRITE,
                    MAP_PAGE_AUTO_RELEASE_ALLOC_HEAP)};

                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::safe_uintmax::failure();
                }

                m_heap_virt += HYPERVISOR_PAGE_SIZE;
            }

            auto const ret{this->update_direct_map_rpts(mut_tls)};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uintmax::failure();
            }

            return old_heap_virt;
        }

        /// <!-- description -->
        ///   @brief Maps a page into the direct map portion of the current
        ///     direct map root page table that is active.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param page_virt the virtual address to map the physical address too
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        map_page_direct(
            tls_t &mut_tls, page_pool_t &mut_page_pool, bsl::safe_uintmax const &page_virt) noexcept
            -> bsl::errc_type
        {
            constexpr auto dm_addr{HYPERVISOR_EXT_DIRECT_MAP_ADDR};
            constexpr auto dm_size{HYPERVISOR_EXT_DIRECT_MAP_SIZE};

            if (bsl::unlikely(page_virt < dm_addr)) {
                return bsl::errc_failure;
            }

            if (bsl::unlikely(page_virt >= dm_addr + dm_size)) {
                return bsl::errc_failure;
            }

            auto *const pmut_direct_map_rpt{
                m_direct_map_rpts.at_if(bsl::to_umax(mut_tls.active_vmid))};
            if (bsl::unlikely(nullptr == pmut_direct_map_rpt)) {
                bsl::error() << "invalid active_vmid "           // --
                             << bsl::hex(mut_tls.active_vmid)    // --
                             << bsl::endl                        // --
                             << bsl::here();                     // --

                return bsl::errc_failure;
            }

            auto const ret{pmut_direct_map_rpt->map_page_unaligned(
                mut_tls,
                mut_page_pool,
                page_virt,
                page_virt - dm_addr,
                MAP_PAGE_READ | MAP_PAGE_WRITE,
                MAP_PAGE_NO_AUTO_RELEASE)};

            if (ret == bsl::errc_already_exists) {
                return bsl::errc_success;
            }

            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            return ret;
        }

        /// <!-- description -->
        ///   @brief Tells the extension that a VM was created so that it
        ///     can initialize it's VM specific resources.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param vmid the VMID of the VM that was created.
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        signal_vm_created(
            tls_t &mut_tls, page_pool_t &mut_page_pool, bsl::safe_uint16 const &vmid) noexcept
            -> bsl::errc_type
        {
            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "ext_t not initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            auto *const pmut_rpt{m_direct_map_rpts.at_if(bsl::to_umax(vmid))};
            if (bsl::unlikely_assert(nullptr == pmut_rpt)) {
                bsl::error() << "vmid "                                                  // --
                             << bsl::hex(vmid)                                           // --
                             << " is invalid or greater than the HYPERVISOR_MAX_VMS "    // --
                             << bsl::hex(HYPERVISOR_MAX_VMS)                             // --
                             << bsl::endl                                                // --
                             << bsl::here();                                             // --

                return bsl::errc_failure;
            }

            auto const ret{this->initialize_direct_map_rpt(mut_tls, mut_page_pool, *pmut_rpt)};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            return ret;
        }

        /// <!-- description -->
        ///   @brief Tells the extension that a VM was destroyed so that it
        ///     can release it's VM specific resources.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param vmid the VMID of the VM that was destroyed.
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        signal_vm_destroyed(
            tls_t &mut_tls, page_pool_t &mut_page_pool, bsl::safe_uint16 const &vmid) noexcept
            -> bsl::errc_type
        {
            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "ext_t not initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            auto *const pmut_rpt{m_direct_map_rpts.at_if(bsl::to_umax(vmid))};
            if (bsl::unlikely_assert(nullptr == pmut_rpt)) {
                bsl::error() << "vmid "                                                  // --
                             << bsl::hex(vmid)                                           // --
                             << " is invalid or greater than the HYPERVISOR_MAX_VMS "    // --
                             << bsl::hex(HYPERVISOR_MAX_VMS)                             // --
                             << bsl::endl                                                // --
                             << bsl::here();                                             // --

                return bsl::errc_failure;
            }

            pmut_rpt->release(mut_tls, mut_page_pool);
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Starts the extension by executing it's _start entry point.
        ///     If the extension has not been initialized, this function will
        ///     return bsl::errc_success.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsic_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        start(tls_t &mut_tls, intrinsic_t &mut_intrinsic) noexcept -> bsl::errc_type
        {
            auto const arg{bsl::to_umax(syscall::BF_ALL_SPECS_SUPPORTED_VAL)};
            auto const ret{this->execute(mut_tls, mut_intrinsic, m_entry_ip, arg)};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            m_started = true;
            return ret;
        }

        /// <!-- description -->
        ///   @brief Bootstraps the extension by executing it's bootstrap entry
        ///     point. If the extension has not been initialized, this function
        ///     will return bsl::errc_success.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsic_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        bootstrap(tls_t &mut_tls, intrinsic_t &mut_intrinsic) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely(!m_bootstrap_ip)) {
                bsl::error() << "a bootstrap handler was never registered\n" << bsl::here();
                return bsl::errc_failure;
            }

            auto const arg{bsl::to_umax(mut_tls.ppid)};
            auto const ret{this->execute(mut_tls, mut_intrinsic, m_bootstrap_ip, arg)};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            return ret;
        }

        /// <!-- description -->
        ///   @brief Bootstraps the extension by executing it's bootstrap entry
        ///     point. If the extension has not been initialized, this function
        ///     will return bsl::errc_success.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsic_t to use
        ///   @param exit_reason the reason for the VMExit
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        vmexit(
            tls_t &mut_tls,
            intrinsic_t &mut_intrinsic,
            bsl::safe_uintmax const &exit_reason) noexcept -> bsl::errc_type
        {
            auto const arg0{bsl::to_umax(mut_tls.active_vpsid)};
            auto const arg1{exit_reason};

            auto const ret{this->execute(mut_tls, mut_intrinsic, m_vmexit_ip, arg0, arg1)};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            return ret;
        }

        /// <!-- description -->
        ///   @brief Bootstraps the extension by executing it's bootstrap entry
        ///     point. If the extension has not been initialized, this function
        ///     will return bsl::errc_success.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsic_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        fail(tls_t &mut_tls, intrinsic_t &mut_intrinsic) noexcept -> bsl::errc_type
        {
            auto const arg0{syscall::BF_STATUS_FAILURE_UNKNOWN};
            auto const ret{this->execute(mut_tls, mut_intrinsic, m_fail_ip, arg0)};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            return ret;
        }

        /// <!-- description -->
        ///   @brief Dumps the vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///
        constexpr void
        dump(tls_t const &tls, page_pool_t const &page_pool) const noexcept
        {
            if constexpr (BSL_DEBUG_LEVEL == bsl::CRITICAL_ONLY) {
                return;
            }

            if (bsl::unlikely_assert(!m_id)) {
                bsl::print() << "[error]" << bsl::endl;
                return;
            }

            bsl::print() << bsl::mag << "ext [";
            bsl::print() << bsl::rst << bsl::hex(m_id);
            bsl::print() << bsl::mag << "] dump: ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Header
            ///

            bsl::print() << bsl::ylw << "+------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::cyn << bsl::fmt{"^14s", "description "};
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::cyn << bsl::fmt{"^19s", "value "};
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            bsl::print() << bsl::ylw << "+------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            /// Started
            ///

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<14s", "started "};
            bsl::print() << bsl::ylw << "| ";
            if (m_started) {
                bsl::print() << bsl::grn << bsl::fmt{"^19s", "yes "};
            }
            else {
                bsl::print() << bsl::red << bsl::fmt{"^19s", "no "};
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Active
            ///

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<14s", "active "};
            bsl::print() << bsl::ylw << "| ";
            if (tls.active_extid == m_id) {
                bsl::print() << bsl::grn << bsl::fmt{"^19s", "yes "};
            }
            else {
                bsl::print() << bsl::red << bsl::fmt{"^19s", "no "};
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Entry IP
            ///

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<14s", "entry ip "};
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::hex(m_entry_ip) << ' ';
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Bootstrap IP
            ///

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<14s", "bootstrap ip "};
            bsl::print() << bsl::ylw << "| ";
            if (m_bootstrap_ip) {
                bsl::print() << bsl::rst << bsl::hex(m_bootstrap_ip) << ' ';
            }
            else {
                bsl::print() << bsl::red << bsl::fmt{"^19s", "not registered "};
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// VMExit IP
            ///

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<14s", "vmexit ip "};
            bsl::print() << bsl::ylw << "| ";
            if (m_vmexit_ip) {
                bsl::print() << bsl::rst << bsl::hex(m_vmexit_ip) << ' ';
            }
            else {
                bsl::print() << bsl::red << bsl::fmt{"^19s", "not registered "};
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Fail IP
            ///

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<14s", "fail ip "};
            bsl::print() << bsl::ylw << "| ";
            if (m_fail_ip) {
                bsl::print() << bsl::rst << bsl::hex(m_fail_ip) << ' ';
            }
            else {
                bsl::print() << bsl::red << bsl::fmt{"^19s", "not registered "};
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Handle
            ///

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<14s", "handle "};
            bsl::print() << bsl::ylw << "| ";
            if (m_handle) {
                bsl::print() << bsl::rst << bsl::hex(m_handle) << ' ';
            }
            else {
                bsl::print() << bsl::red << bsl::fmt{"^19s", "not opened "};
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Heap Cursor
            ///

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<14s", "heap cursor "};
            bsl::print() << bsl::ylw << "| ";
            if (!m_heap_virt.is_zero()) {
                bsl::print() << bsl::rst << bsl::hex(m_heap_virt) << ' ';
            }
            else {
                bsl::print() << bsl::red << bsl::fmt{"^19s", "not allocated "};
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Footer
            ///

            bsl::print() << bsl::ylw << "+------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            auto const *const direct_map_rpt{
                m_direct_map_rpts.at_if(bsl::to_umax(tls.active_vmid))};
            if (bsl::unlikely(nullptr == direct_map_rpt)) {
                bsl::error() << "invalid active_vmid "       // --
                             << bsl::hex(tls.active_vmid)    // --
                             << bsl::endl                    // --
                             << bsl::here();                 // --

                return;
            }

            bsl::print() << bsl::rst << bsl::endl;

            bsl::print() << bsl::mag << "ext [";
            bsl::print() << bsl::rst << bsl::hex(m_id);
            bsl::print() << bsl::mag << "] direct map dump: ";
            bsl::print() << bsl::rst << bsl::endl;

            direct_map_rpt->dump(page_pool);
        }
    };
}

#endif
