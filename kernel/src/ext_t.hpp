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
#include <huge_pool_t.hpp>
#include <intrinsic_t.hpp>
#include <map_page_flags.hpp>
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
        bsl::safe_uintmax m_heap_crsr{};

        /// <!-- description -->
        ///   @brief Validates the provided pt_load segment.
        ///
        /// <!-- inputs/outputs -->
        ///   @param phdr the pt_load segment to validate
        ///   @param elf_file the ELF file to validate against
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        validate_pt_load(
            bfelf::elf64_phdr_t const *const phdr,
            bsl::span<bsl::uint8 const> const &elf_file) noexcept -> bsl::errc_type
        {
            if ((bsl::to_u32(phdr->p_flags) & bfelf::PF_X).is_pos()) {
                if (bsl::unlikely((bsl::to_u32(phdr->p_flags) & bfelf::PF_W).is_pos())) {
                    bsl::error() << "ELF code segment flags not supported\n" << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

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

            if (bsl::unlikely(bsl::to_umax(phdr->p_offset) > elf_file.size())) {
                bsl::error() << "ELF code segment offset invalid\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(bsl::to_umax(phdr->p_vaddr) < HYPERVISOR_EXT_CODE_ADDR)) {
                bsl::error() << "ELF code segment virtual address not supported\n" << bsl::here();
                return bsl::errc_failure;
            }

            auto const required_memsz{bsl::to_umax(phdr->p_vaddr) + bsl::to_umax(phdr->p_memsz)};
            if (bsl::unlikely(
                    required_memsz > (HYPERVISOR_EXT_CODE_ADDR + HYPERVISOR_EXT_CODE_SIZE))) {
                bsl::error() << "ELF code segment virtual address not supported\n" << bsl::here();
                return bsl::errc_failure;
            }

            auto const required_filesz{bsl::to_umax(phdr->p_filesz) + bsl::to_umax(phdr->p_offset)};
            if (bsl::unlikely(required_filesz > elf_file.size())) {
                bsl::error() << "ELF code segment filesz invalid\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(bsl::to_umax(phdr->p_memsz) > HYPERVISOR_EXT_CODE_SIZE)) {
                bsl::error() << "ELF code segment memsz invalid\n" << bsl::here();
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
        ///   @param elf_file the ELF file to validate against
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        validate_pt_tls(
            bfelf::elf64_phdr_t const *const phdr,
            bsl::span<bsl::uint8 const> const &elf_file) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely((bsl::to_u32(phdr->p_flags) & bfelf::PF_X).is_pos())) {
                bsl::error() << "Executable TLS blocks are not supported\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(bsl::to_umax(phdr->p_offset) > elf_file.size())) {
                bsl::error() << "ELF TLS segment offset invalid\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(bsl::to_umax(phdr->p_vaddr) < HYPERVISOR_EXT_CODE_ADDR)) {
                bsl::error() << "ELF TLS segment virtual address not supported\n" << bsl::here();
                return bsl::errc_failure;
            }

            auto const required_memsz{bsl::to_umax(phdr->p_vaddr) + bsl::to_umax(phdr->p_memsz)};
            if (bsl::unlikely(
                    required_memsz > (HYPERVISOR_EXT_CODE_ADDR + HYPERVISOR_EXT_CODE_SIZE))) {
                bsl::error() << "ELF TLS segment virtual address not supported\n" << bsl::here();
                return bsl::errc_failure;
            }

            auto const required_filesz{bsl::to_umax(phdr->p_filesz) + bsl::to_umax(phdr->p_offset)};
            if (bsl::unlikely(required_filesz > elf_file.size())) {
                bsl::error() << "ELF TLS segment filesz invalid\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(bsl::to_umax(phdr->p_memsz) > HYPERVISOR_PAGE_SIZE)) {
                bsl::error() << "ELF TLS segment memsz invalid\n" << bsl::here();
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Validates the provided ELF file.
        ///
        /// <!-- inputs/outputs -->
        ///   @param elf_file the ELF file to validate against
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        validate(bsl::span<bsl::uint8 const> const &elf_file) noexcept -> bsl::errc_type
        {
            if constexpr (BSL_RELEASE_MODE) {
                return bsl::errc_success;
            }

            if (bsl::unlikely(!bfelf::validate_elf64_ehdr(elf_file))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            auto const phdrtab{bfelf::get_elf64_phdrtab(elf_file)};
            if (bsl::unlikely(phdrtab.empty())) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            /// TODO:
            /// - Add support for GNU RELOC segments so that we can set
            ///   the RW permissions properly
            ///

            bool found_pt_load{};
            bool found_pt_gnu_stack{};

            for (auto const elem : phdrtab) {
                switch (elem.data->p_type) {
                    case bfelf::PT_LOAD.get(): {
                        found_pt_load = true;
                        if (bsl::unlikely(!validate_pt_load(elem.data, elf_file))) {
                            bsl::print<bsl::V>() << bsl::here();
                            return bsl::errc_failure;
                        }
                        break;
                    }

                    case bfelf::PT_GNU_STACK.get(): {
                        found_pt_gnu_stack = true;
                        if (bsl::unlikely(!validate_pt_gnu_stack(elem.data))) {
                            bsl::print<bsl::V>() << bsl::here();
                            return bsl::errc_failure;
                        }
                        break;
                    }

                    case bfelf::PT_TLS.get(): {
                        if (bsl::unlikely(!validate_pt_tls(elem.data, elf_file))) {
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

            if (bsl::unlikely(!found_pt_load)) {
                bsl::error() << "PT_LOAD segments missing from ELF file\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!found_pt_gnu_stack)) {
                bsl::error() << "PT_GNU_STACK segment missing from ELF file\n" << bsl::here();
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds all of the program segments given an ELF file to
        ///     the provided root page table.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param rpt the root page table to add too
        ///   @param elf_file the ELF file that contains the segment info
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        add_segments(
            tls_t &tls,
            page_pool_t &page_pool,
            root_page_table_t &rpt,
            bsl::span<bsl::uint8 const> const &elf_file) noexcept -> bsl::errc_type
        {
            bsl::span<bsl::uint8> page{};

            auto const phdrtab{bfelf::get_elf64_phdrtab(elf_file)};
            for (auto const elem : phdrtab) {
                auto const *const phdr{elem.data};

                if (bfelf::PT_LOAD != phdr->p_type) {
                    continue;
                }

                bsl::safe_uintmax const bytes_to_allocate{phdr->p_memsz};
                bsl::safe_uintmax bytes_to_copy{phdr->p_filesz};

                constexpr auto offset{1_umax};
                bsl::safe_uintmax bytes_to_next_page{HYPERVISOR_PAGE_SIZE};
                bsl::safe_uintmax bytes_into_page{phdr->p_vaddr & (HYPERVISOR_PAGE_SIZE - offset)};

                if (bytes_into_page.is_pos()) {
                    bytes_to_next_page -= bytes_into_page;
                }
                else {
                    bsl::touch();
                }

                bsl::safe_uintmax bytes{};
                while (bytes < bytes_to_allocate) {

                    if (bytes_to_next_page == HYPERVISOR_PAGE_SIZE) {
                        if ((phdr->p_flags & bfelf::PF_X).is_pos()) {
                            page = bsl::as_writable_t<bsl::uint8>(
                                rpt.allocate_page_rx(
                                    tls,
                                    page_pool,
                                    phdr->p_vaddr + bytes,
                                    MAP_PAGE_AUTO_RELEASE_ELF),
                                HYPERVISOR_PAGE_SIZE);
                        }
                        else {
                            page = bsl::as_writable_t<bsl::uint8>(
                                rpt.allocate_page_rw(
                                    tls,
                                    page_pool,
                                    phdr->p_vaddr + bytes,
                                    MAP_PAGE_AUTO_RELEASE_ELF),
                                HYPERVISOR_PAGE_SIZE);
                        }

                        if (bsl::unlikely(!page)) {
                            bsl::print<bsl::V>() << bsl::here();
                            return bsl::errc_failure;
                        }

                        bsl::touch();
                    }
                    else {
                        if (bsl::unlikely_assert(!page)) {
                            bsl::error() << "The first ELF segment is invalid\n" << bsl::here();
                            return bsl::errc_failure;
                        }

                        bsl::touch();
                    }

                    if (bytes_to_copy.is_pos()) {
                        bsl::safe_uintmax bytes_to_copy_in_this_page{bytes_to_copy};
                        if (bytes_to_copy_in_this_page > bytes_to_next_page) {
                            bytes_to_copy_in_this_page = bytes_to_next_page;
                        }
                        else {
                            bsl::touch();
                        }

                        auto *const dst_addr{page.at_if(bytes_into_page)};
                        if (bsl::unlikely_assert(nullptr == dst_addr)) {
                            bsl::print<bsl::V>() << bsl::here();
                            return bsl::errc_failure;
                        }

                        auto const *const src_addr{elf_file.at_if(phdr->p_offset + bytes)};
                        if (bsl::unlikely_assert(nullptr == src_addr)) {
                            bsl::print<bsl::V>() << bsl::here();
                            return bsl::errc_failure;
                        }

                        bsl::builtin_memcpy(dst_addr, src_addr, bytes_to_copy_in_this_page);
                        bytes_to_copy -= bytes_to_copy_in_this_page;
                    }
                    else {
                        bsl::touch();
                    }

                    constexpr auto reset{0_umax};
                    bytes += bytes_to_next_page;
                    bytes_to_next_page = HYPERVISOR_PAGE_SIZE;
                    bytes_into_page = reset;
                }
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds an exteneion's stack for a specific PP to the
        ///     provided root page table at the provided address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param rpt the root page table to add too
        ///   @param addr the address of where to put the stack
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        add_stack(
            tls_t &tls,
            page_pool_t &page_pool,
            root_page_table_t &rpt,
            bsl::safe_uintmax const &addr) noexcept -> bsl::errc_type
        {
            for (bsl::safe_uintmax bytes{}; bytes < HYPERVISOR_EXT_STACK_SIZE;
                 bytes += HYPERVISOR_PAGE_SIZE) {
                auto const *const page{rpt.allocate_page_rw(
                    tls, page_pool, addr + bytes, MAP_PAGE_AUTO_RELEASE_STACK)};
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
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param rpt the root page table to add too
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        add_stacks(tls_t &tls, page_pool_t &page_pool, root_page_table_t &rpt) noexcept
            -> bsl::errc_type
        {
            for (bsl::safe_uintmax pp{}; pp < bsl::to_umax(tls.online_pps); ++pp) {
                auto const offs{(HYPERVISOR_EXT_STACK_SIZE + HYPERVISOR_PAGE_SIZE) * pp};
                auto const addr{(HYPERVISOR_EXT_STACK_ADDR + offs)};

                if (bsl::unlikely(!this->add_stack(tls, page_pool, rpt, addr))) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds an exteneion's TLS block for a specific PP to the
        ///     provided root page table at the provided address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param rpt the root page table to add too
        ///   @param addr_usr the address the user's portion of the TLS block
        ///   @param addr_abi the address the ABI's portion of the TLS block
        ///   @param elf_file the ELF file that contains the TLS info
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        add_tls_block(
            tls_t &tls,
            page_pool_t &page_pool,
            root_page_table_t &rpt,
            bsl::safe_uintmax const &addr_usr,
            bsl::safe_uintmax const &addr_abi,
            bsl::span<bsl::uint8 const> const &elf_file) noexcept -> bsl::errc_type
        {
            bsl::span<bsl::uint8> page_usr{};
            bsl::span<bsl::uintmax> page_abi{};

            page_usr = bsl::as_writable_t<bsl::uint8>(
                rpt.allocate_page_rw(tls, page_pool, addr_usr, MAP_PAGE_AUTO_RELEASE_TLS),
                HYPERVISOR_PAGE_SIZE);
            if (bsl::unlikely(!page_usr)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            page_abi = bsl::as_writable_t<bsl::uintmax>(
                rpt.allocate_page_rw(tls, page_pool, addr_abi, MAP_PAGE_AUTO_RELEASE_TLS),
                HYPERVISOR_PAGE_SIZE);
            if (bsl::unlikely(!page_abi)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            *page_abi.front_if() = addr_abi.get();

            auto const phdrtab{bfelf::get_elf64_phdrtab(elf_file)};
            for (auto const elem : phdrtab) {
                auto const *const phdr{elem.data};

                if (bfelf::PT_TLS != phdr->p_type) {
                    continue;
                }

                auto const *const src_addr{elf_file.at_if(phdr->p_offset)};
                auto const dst_index{HYPERVISOR_PAGE_SIZE - bsl::to_umax(phdr->p_memsz)};
                bsl::builtin_memcpy(page_usr.at_if(dst_index), src_addr, phdr->p_memsz);

                return bsl::errc_success;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds the exteneion's TLS block to the provided
        ///     root page table.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param rpt the root page table to add too
        ///   @param elf_file the ELF file that contains the TLS info
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        add_tls_blocks(
            tls_t &tls,
            page_pool_t &page_pool,
            root_page_table_t &rpt,
            bsl::span<bsl::uint8 const> const &elf_file) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};

            for (bsl::safe_uintmax pp{}; pp < bsl::to_umax(tls.online_pps); ++pp) {
                auto const offs{(HYPERVISOR_EXT_TLS_SIZE + HYPERVISOR_PAGE_SIZE) * pp};
                auto const addr{(HYPERVISOR_EXT_TLS_ADDR + offs)};

                ret = this->add_tls_block(
                    tls, page_pool, rpt, addr, addr + HYPERVISOR_PAGE_SIZE, elf_file);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
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
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param rpt the root page table to initialize
        ///   @param system_rpt the system root page table to initialize with
        ///   @param elf_file the ELF file that contains the segment and TLS
        ///      info need to initialize the provided rpt
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize_rpt(
            tls_t &tls,
            page_pool_t &page_pool,
            root_page_table_t &rpt,
            root_page_table_t const &system_rpt,
            bsl::span<bsl::uint8 const> const &elf_file) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely(!rpt.initialize(tls, page_pool))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            bsl::finally release_on_error{[&tls, &rpt, &page_pool]() noexcept -> void {
                rpt.release(tls, page_pool);
            }};

            if (bsl::unlikely(!rpt.add_tables(tls, system_rpt))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->add_segments(tls, page_pool, rpt, elf_file))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->add_stacks(tls, page_pool, rpt))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->add_tls_blocks(tls, page_pool, rpt, elf_file))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            release_on_error.ignore();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Initializes a direct map root page table to support the
        ///     execution of this extension (with the inclusion of a direct
        ///     map).
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param rpt the root page table to initialize
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize_direct_map_rpt(
            tls_t &tls, page_pool_t &page_pool, root_page_table_t &rpt) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely(!rpt.initialize(tls, page_pool))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            bsl::finally release_on_error{[&tls, &rpt, &page_pool]() noexcept -> void {
                rpt.release(tls, page_pool);
            }};

            if (bsl::unlikely(!rpt.add_tables(tls, m_main_rpt))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            release_on_error.ignore();
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
        ///   @param tls the current TLS block
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        update_direct_map_rpts(tls_t &tls) noexcept -> bsl::errc_type
        {
            for (auto const rpt : m_direct_map_rpts) {
                if (!rpt.data->is_initialized()) {
                    continue;
                }

                if (bsl::unlikely(!rpt.data->add_tables(tls, m_main_rpt))) {
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
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param ip the instruction pointer defining where in the
        ///     extension to start execution at.
        ///   @param arg0 the first argument to pass the extension
        ///   @param arg1 the second argument to pass the extension
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        execute(
            tls_t &tls,
            intrinsic_t &intrinsic,
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

            auto *const rpt{m_direct_map_rpts.at_if(bsl::to_umax(tls.active_vmid))};
            if (bsl::unlikely_assert(nullptr == rpt)) {
                bsl::error() << "invalid active_vmid "       // --
                             << bsl::hex(tls.active_vmid)    // --
                             << bsl::endl                    // --
                             << bsl::here();                 // --

                return bsl::errc_failure;
            }

            if (tls.active_rpt != rpt) {
                if (bsl::unlikely_assert(!rpt->activate(intrinsic))) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                tls.active_rpt = rpt;
            }
            else {
                bsl::touch();
            }

            if (tls.ext != this) {
                tls.ext = this;
                tls.active_extid = m_id.get();
            }
            else {
                bsl::touch();
            }

            bsl::exit_code const ret{call_ext(ip.get(), tls.sp, arg0.get(), arg1.get())};
            if (bsl::unlikely(ret != bsl::exit_success)) {
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
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param i the ID for this ext_t
        ///   @param ext_elf_file the ELF file for this ext_t
        ///   @param system_rpt the system RPT provided by the loader
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(
            tls_t &tls,
            page_pool_t &page_pool,
            bsl::safe_uint16 const &i,
            loader::ext_elf_file_type const &ext_elf_file,
            root_page_table_t const &system_rpt) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};

            if (bsl::unlikely_assert(m_id)) {
                bsl::error() << "ext_t already initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            bsl::finally release_on_error{[this, &tls, &page_pool]() noexcept -> void {
                this->release(tls, page_pool);
            }};

            if (bsl::unlikely_assert(!i)) {
                bsl::error() << "invalid id\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(!validate(ext_elf_file))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = this->initialize_rpt(tls, page_pool, m_main_rpt, system_rpt, ext_elf_file);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            m_entry_ip = bfelf::get_elf64_ip(ext_elf_file);
            if (bsl::unlikely_assert(!m_entry_ip)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            release_on_error.ignore();

            m_id = i;
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Release the ext_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///
        constexpr void
        release(tls_t &tls, page_pool_t &page_pool) noexcept
        {
            m_heap_crsr = {};
            m_handle = bsl::safe_uintmax::failure();
            m_fail_ip = bsl::safe_uintmax::failure();
            m_vmexit_ip = bsl::safe_uintmax::failure();
            m_bootstrap_ip = bsl::safe_uintmax::failure();
            m_entry_ip = bsl::safe_uintmax::failure();

            for (auto const rpt : m_direct_map_rpts) {
                rpt.data->release(tls, page_pool);
            }

            m_main_rpt.release(tls, page_pool);

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
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @return Returns a alloc_page_t containing the virtual address and
        ///     physical address of the page. If an error occurs, this
        ///     function will return an invalid virtual and physical address.
        ///
        [[nodiscard]] constexpr auto
        alloc_page(tls_t &tls, page_pool_t &page_pool) noexcept -> alloc_page_t
        {
            bsl::errc_type ret{};

            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "ext_t not initialized\n" << bsl::here();
                return {bsl::safe_uintmax::failure(), bsl::safe_uintmax::failure()};
            }

            auto const *const page{
                page_pool.allocate<page_t>(tls, ALLOCATE_TAG_BF_MEM_OP_ALLOC_PAGE)};
            if (bsl::unlikely(nullptr == page)) {
                bsl::print<bsl::V>() << bsl::here();
                return {bsl::safe_uintmax::failure(), bsl::safe_uintmax::failure()};
            }

            auto const page_phys{page_pool.virt_to_phys(page)};
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

            ret = m_direct_map_rpts.front().map_page(
                tls,
                page_pool,
                page_virt,
                page_phys,
                MAP_PAGE_READ | MAP_PAGE_WRITE,
                MAP_PAGE_AUTO_RELEASE_ALLOC_PAGE);

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
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param huge_pool the huge_pool_t to use
        ///   @param size the total number of bytes to allocate
        ///   @return Returns a huge_t containing the virtual address and
        ///     physical address of the memory block. If an error occurs, this
        ///     function will return an invalid virtual and physical address.
        ///
        [[nodiscard]] constexpr auto
        alloc_huge(
            tls_t &tls,
            page_pool_t &page_pool,
            huge_pool_t &huge_pool,
            bsl::safe_uintmax const &size) noexcept -> alloc_huge_t
        {
            bsl::errc_type ret{};

            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "ext_t not initialized\n" << bsl::here();
                return {bsl::safe_uintmax::failure(), bsl::safe_uintmax::failure()};
            }

            constexpr auto aligned{0_umax};
            if (bsl::unlikely((size % HYPERVISOR_PAGE_SIZE) != aligned)) {
                bsl::error() << "invalid size "    // --
                             << bsl::hex(size)     // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return {bsl::safe_uintmax::failure(), bsl::safe_uintmax::failure()};
            }

            auto const huge{huge_pool.allocate(tls, size)};
            if (bsl::unlikely(!huge)) {
                bsl::print<bsl::V>() << bsl::here();
                return {bsl::safe_uintmax::failure(), bsl::safe_uintmax::failure()};
            }

            auto const huge_phys{huge_pool.virt_to_phys(huge.data())};
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

            for (bsl::safe_uintmax i{}; i < size; i += HYPERVISOR_PAGE_SIZE) {
                ret = m_direct_map_rpts.front().map_page(
                    tls,
                    page_pool,
                    huge_virt + i,
                    huge_phys + i,
                    MAP_PAGE_READ | MAP_PAGE_WRITE,
                    MAP_PAGE_AUTO_RELEASE_ALLOC_HUGE);

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
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param size the total number of bytes to allocate and add
        ///     to the heap.
        ///   @return On success, alloc_heap returns the previous address
        ///     virtual address of the heap. If an error occurs, this
        ///     function returns bsl::safe_uintmax::failure().
        ///
        [[nodiscard]] constexpr auto
        alloc_heap(tls_t &tls, page_pool_t &page_pool, bsl::safe_uintmax const &size) noexcept
            -> bsl::safe_uintmax
        {
            bsl::errc_type ret{};

            constexpr auto pool_addr{HYPERVISOR_EXT_HEAP_POOL_ADDR};
            constexpr auto pool_size{HYPERVISOR_EXT_HEAP_POOL_SIZE};

            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "ext_t not initialized\n" << bsl::here();
                return bsl::safe_uintmax::failure();
            }

            if (bsl::unlikely(!size)) {
                bsl::error() << "invalid size "    // --
                             << bsl::hex(size)     // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return bsl::safe_uintmax::failure();
            }

            constexpr auto aligned{0_umax};
            auto pages{size / HYPERVISOR_PAGE_SIZE};

            if ((size % HYPERVISOR_PAGE_SIZE) != aligned) {
                ++pages;
            }
            else {
                bsl::touch();
            }

            if (bsl::unlikely((m_heap_crsr + (pages * HYPERVISOR_PAGE_SIZE)) > pool_size)) {
                bsl::error() << "the extension's heap pool is out of memory"    // --
                             << bsl::endl                                       // --
                             << bsl::here();                                    // --

                return bsl::safe_uintmax::failure();
            }

            auto const previous_heap_virt{m_heap_crsr + pool_addr};
            if (bsl::unlikely_assert(!previous_heap_virt)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uintmax::failure();
            }

            for (bsl::safe_uintmax i{}; i < pages; ++i) {
                auto const *const page{
                    page_pool.allocate<page_t>(tls, ALLOCATE_TAG_BF_MEM_OP_ALLOC_HEAP)};
                if (bsl::unlikely(nullptr == page)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::safe_uintmax::failure();
                }

                auto const page_phys{page_pool.virt_to_phys(page)};
                if (bsl::unlikely_assert(!page_phys)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::safe_uintmax::failure();
                }

                auto const page_virt{m_heap_crsr + pool_addr};
                if (bsl::unlikely_assert(!page_virt)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::safe_uintmax::failure();
                }

                ret = m_main_rpt.map_page(
                    tls,
                    page_pool,
                    page_virt,
                    page_phys,
                    MAP_PAGE_READ | MAP_PAGE_WRITE,
                    MAP_PAGE_AUTO_RELEASE_ALLOC_HEAP);

                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::safe_uintmax::failure();
                }

                m_heap_crsr += HYPERVISOR_PAGE_SIZE;
            }

            ret = this->update_direct_map_rpts(tls);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uintmax::failure();
            }

            return previous_heap_virt;
        }

        /// <!-- description -->
        ///   @brief Maps a page into the direct map portion of the current
        ///     direct map root page table that is active.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param page_virt the virtual address to map the physical address too
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        map_page_direct(
            tls_t &tls, page_pool_t &page_pool, bsl::safe_uintmax const &page_virt) noexcept
            -> bsl::errc_type
        {
            bsl::errc_type ret{};

            constexpr auto dm_addr{HYPERVISOR_EXT_DIRECT_MAP_ADDR};
            constexpr auto dm_size{HYPERVISOR_EXT_DIRECT_MAP_SIZE};

            constexpr auto offset{1_umax};
            constexpr auto min_dm_addr{dm_addr};
            constexpr auto max_dm_addr{dm_addr + (dm_size - offset)};

            if (bsl::unlikely(page_virt < min_dm_addr)) {
                return bsl::errc_failure;
            }

            if (bsl::unlikely(page_virt > max_dm_addr)) {
                return bsl::errc_failure;
            }

            auto *const direct_map_rpt{m_direct_map_rpts.at_if(bsl::to_umax(tls.active_vmid))};
            if (bsl::unlikely(nullptr == direct_map_rpt)) {
                bsl::error() << "invalid active_vmid "       // --
                             << bsl::hex(tls.active_vmid)    // --
                             << bsl::endl                    // --
                             << bsl::here();                 // --

                return bsl::errc_failure;
            }

            ret = direct_map_rpt->map_page_unaligned(
                tls,
                page_pool,
                page_virt,
                page_virt - min_dm_addr,
                MAP_PAGE_READ | MAP_PAGE_WRITE,
                MAP_PAGE_NO_AUTO_RELEASE);

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
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param vmid the VMID of the VM that was created.
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        signal_vm_created(tls_t &tls, page_pool_t &page_pool, bsl::safe_uint16 const &vmid) noexcept
            -> bsl::errc_type
        {
            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "ext_t not initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            auto *const rpt{m_direct_map_rpts.at_if(bsl::to_umax(vmid))};
            if (bsl::unlikely_assert(nullptr == rpt)) {
                bsl::error() << "vmid "                                                  // --
                             << bsl::hex(vmid)                                           // --
                             << " is invalid or greater than the HYPERVISOR_MAX_VMS "    // --
                             << bsl::hex(HYPERVISOR_MAX_VMS)                             // --
                             << bsl::endl                                                // --
                             << bsl::here();                                             // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->initialize_direct_map_rpt(tls, page_pool, *rpt))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Tells the extension that a VM was destroyed so that it
        ///     can release it's VM specific resources.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param vmid the VMID of the VM that was destroyed.
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        signal_vm_destroyed(
            tls_t &tls, page_pool_t &page_pool, bsl::safe_uint16 const &vmid) noexcept
            -> bsl::errc_type
        {
            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "ext_t not initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            auto *const rpt{m_direct_map_rpts.at_if(bsl::to_umax(vmid))};
            if (bsl::unlikely_assert(nullptr == rpt)) {
                bsl::error() << "vmid "                                                  // --
                             << bsl::hex(vmid)                                           // --
                             << " is invalid or greater than the HYPERVISOR_MAX_VMS "    // --
                             << bsl::hex(HYPERVISOR_MAX_VMS)                             // --
                             << bsl::endl                                                // --
                             << bsl::here();                                             // --

                return bsl::errc_failure;
            }

            rpt->release(tls, page_pool);
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Starts the extension by executing it's _start entry point.
        ///     If the extension has not been initialized, this function will
        ///     return bsl::errc_success.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        start(tls_t &tls, intrinsic_t &intrinsic) noexcept -> bsl::errc_type
        {
            auto const arg{bsl::to_umax(syscall::BF_ALL_SPECS_SUPPORTED_VAL)};
            auto const ret{this->execute(tls, intrinsic, m_entry_ip, arg)};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            m_started = true;
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Bootstraps the extension by executing it's bootstrap entry
        ///     point. If the extension has not been initialized, this function
        ///     will return bsl::errc_success.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        bootstrap(tls_t &tls, intrinsic_t &intrinsic) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely(!m_bootstrap_ip)) {
                bsl::error() << "a bootstrap handler was never registered\n" << bsl::here();
                return bsl::errc_failure;
            }

            auto const arg{bsl::to_umax(tls.ppid)};
            auto const ret{this->execute(tls, intrinsic, m_bootstrap_ip, arg)};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Bootstraps the extension by executing it's bootstrap entry
        ///     point. If the extension has not been initialized, this function
        ///     will return bsl::errc_success.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param exit_reason the reason for the VMExit
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        vmexit(tls_t &tls, intrinsic_t &intrinsic, bsl::safe_uintmax const &exit_reason) noexcept
            -> bsl::errc_type
        {
            bsl::safe_uintmax arg0{bsl::to_umax(tls.active_vpsid)};
            bsl::safe_uintmax arg1{exit_reason};

            auto const ret{this->execute(tls, intrinsic, m_vmexit_ip, arg0, arg1)};
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
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        fail(tls_t &tls, intrinsic_t &intrinsic) noexcept -> bsl::errc_type
        {
            bsl::safe_uintmax arg0{syscall::BF_STATUS_FAILURE_UNKNOWN};

            auto const ret{this->execute(tls, intrinsic, m_fail_ip, arg0)};
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
        dump(tls_t &tls, page_pool_t &page_pool) const noexcept
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
            if (!m_heap_crsr.is_zero()) {
                bsl::print() << bsl::rst << bsl::hex(m_heap_crsr) << ' ';
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
