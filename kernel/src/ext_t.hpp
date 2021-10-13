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
#include <basic_alloc_page_t.hpp>
#include <basic_page_4k_t.hpp>
#include <basic_root_page_table_t.hpp>
#include <bf_constants.hpp>
#include <bfelf/elf64_ehdr_t.hpp>
#include <bfelf/elf64_phdr_t.hpp>
#include <call_ext.hpp>
#include <ext_tcb_t.hpp>
#include <huge_pool_t.hpp>
#include <intrinsic_t.hpp>
#include <map_page_flags.hpp>
#include <mk_args_t.hpp>
#include <page_4k_t.hpp>
#include <page_aligned_bytes_t.hpp>
#include <page_pool_t.hpp>
#include <root_page_table_t.hpp>
#include <tls_t.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/cstring.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/ensures.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/expects.hpp>
#include <bsl/finally.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/span.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

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
    /// <!-- description -->
    ///   @brief Defines an extension WRT to the microkernel. Whenever an
    ///     executes, it must go through this class to do so. This class
    ///     also maintains all of the resources given to an extension, as
    ///     well as the extension's memory map, ELF file, stack, TLS blocks,
    ///     and all of it's memory map functions.
    ///
    class ext_t final
    {
        /// @brief stores the ID associated with this ext_t
        bsl::safe_u16 m_id{};
        /// @brief stores the extension's handle
        bsl::safe_u64 m_handle{};
        /// @brief stores true if start() has been executed
        bool m_has_executed_start{};
        /// @brief stores true if fail_entry() is being executed
        bool m_is_executing_fail{};

        /// @brief stores the main rpt
        root_page_table_t m_main_rpt{};
        /// @brief stores the direct map rpts
        bsl::array<root_page_table_t, HYPERVISOR_MAX_VMS.get()> m_direct_map_rpts{};

        /// @brief stores the main IP registered by the extension
        bsl::safe_u64 m_entry_ip{};
        /// @brief stores the bootstrap IP registered by the extension
        bsl::safe_u64 m_bootstrap_ip{};
        /// @brief stores the vmexit IP registered by the extension
        bsl::safe_u64 m_vmexit_ip{};
        /// @brief stores the fail IP registered by the extension
        bsl::safe_u64 m_fail_ip{};

        /// @brief stores the direct map rpts
        bsl::array<bsl::span<page_4k_t>, HYPERVISOR_MAX_HUGE_ALLOCS.get()> m_huge_allocs{};
        /// @brief stores the index into m_huge_allocs
        bsl::safe_idx m_huge_allocs_idx{};

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
            return {file->e_phdr, bsl::to_umx(file->e_phnum)};
        }

        /// <!-- description -->
        ///   @brief Returns "size" as a "page_aligned_bytes_t"
        ///
        /// <!-- inputs/outputs -->
        ///   @param size the number of bytes to convert
        ///   @return Returns "size" as a "page_aligned_bytes_t". On error,
        ///     check the bytes field.
        ///
        [[nodiscard]] static constexpr auto
        size_to_page_aligned_bytes(bsl::safe_umx const &size) noexcept -> page_aligned_bytes_t
        {
            bsl::safe_umx mut_pages{};
            if ((size % HYPERVISOR_PAGE_SIZE).checked().is_zero()) {
                mut_pages = size >> HYPERVISOR_PAGE_SHIFT;
            }
            else {
                mut_pages = (size >> HYPERVISOR_PAGE_SHIFT) + bsl::safe_umx::magic_1();
            }

            /// NOTE:
            /// - We do not validate the bytes field. This is because the size
            ///   field could be anything as it comes from the syscall
            ///   interface, which means it absolutely could overflow. Callers
            ///   of this function will have to check for this.
            /// - We do mark pages as checked as it is impossible for it to
            ///   overflow.

            return {mut_pages * HYPERVISOR_PAGE_SIZE, mut_pages.checked()};
        }

        /// <!-- description -->
        ///   @brief Checks whether or not a given ELF file is in a format that
        ///     this ELF loader can handle.
        ///
        /// <!-- inputs/outputs -->
        ///   @param file a pointer to the elf file
        ///
        static constexpr void
        validate_elf64_ehdr(bfelf::elf64_ehdr_t const *const file) noexcept
        {
            bsl::expects(nullptr != file);

            bsl::expects(file->e_type == bfelf::ET_EXEC);
            bsl::expects(*file->e_ident.at_if(bfelf::EI_MAG0) == bfelf::ELFMAG0);
            bsl::expects(*file->e_ident.at_if(bfelf::EI_MAG1) == bfelf::ELFMAG1);
            bsl::expects(*file->e_ident.at_if(bfelf::EI_MAG2) == bfelf::ELFMAG2);
            bsl::expects(*file->e_ident.at_if(bfelf::EI_MAG3) == bfelf::ELFMAG3);
            bsl::expects(*file->e_ident.at_if(bfelf::EI_CLASS) == bfelf::ELFCLASS64);
            bsl::expects(*file->e_ident.at_if(bfelf::EI_OSABI) == bfelf::ELFOSABI_SYSV);
        }

        /// <!-- description -->
        ///   @brief Validates the provided pt_load segment.
        ///
        /// <!-- inputs/outputs -->
        ///   @param phdr the pt_load segment to validate
        ///
        static constexpr void
        validate_pt_load(bfelf::elf64_phdr_t const *const phdr) noexcept
        {
            bsl::expects(nullptr != phdr);

            constexpr auto min_vaddr{HYPERVISOR_EXT_CODE_ADDR};
            constexpr auto max_vaddr{(min_vaddr + HYPERVISOR_EXT_CODE_SIZE).checked()};

            bsl::expects((phdr->p_vaddr) >= min_vaddr);
            bsl::expects((phdr->p_vaddr + bsl::to_umx(phdr->p_memsz)).checked() <= max_vaddr);

            if (bsl::safe_u32::magic_0() != (phdr->p_flags & bfelf::PF_W)) {
                bsl::expects(bsl::safe_u32::magic_0() == (phdr->p_flags & bfelf::PF_X));
            }
            else {
                bsl::touch();
            }

            if (bsl::safe_u32::magic_0() != (phdr->p_flags & bfelf::PF_X)) {
                bsl::expects(bsl::safe_u32::magic_0() == (phdr->p_flags & bfelf::PF_W));
            }
            else {
                bsl::touch();
            }

            bsl::expects(phdr->p_align == HYPERVISOR_PAGE_SIZE);
        }

        /// <!-- description -->
        ///   @brief Validates the provided pt_gnu_stack segment.
        ///
        /// <!-- inputs/outputs -->
        ///   @param phdr the pt_gnu_stack segment to validate
        ///
        static constexpr void
        validate_pt_gnu_stack(bfelf::elf64_phdr_t const *const phdr) noexcept
        {
            bsl::expects(nullptr != phdr);
            bsl::expects(bsl::safe_u32::magic_0() == (phdr->p_flags & bfelf::PF_X));
        }

        /// <!-- description -->
        ///   @brief Validates the provided pt_tls segment.
        ///
        /// <!-- inputs/outputs -->
        ///   @param phdr the pt_tls segment to validate
        ///
        static constexpr void
        validate_pt_tls(bfelf::elf64_phdr_t const *const phdr) noexcept
        {
            bsl::expects(nullptr != phdr);
            bsl::expects(phdr->p_memsz <= HYPERVISOR_PAGE_SIZE);
            bsl::expects(bsl::safe_u32::magic_0() == (phdr->p_flags & bfelf::PF_X));
        }

        /// <!-- description -->
        ///   @brief Validates the provided ELF file.
        ///
        /// <!-- inputs/outputs -->
        ///   @param file the elf file to validate
        ///
        static constexpr void
        validate(loader::ext_elf_file_t const *const file) noexcept
        {
            /// NOTE:
            /// - The point of this function is to provide some sanity checks
            ///   in debug mode which is why everything uses bsl::expects.
            ///   None of these are needed in a release build because it
            ///   will have gone through testing to ensure they all pass.
            /// - Removing this logic in a release build helps to keep the
            ///   binary size smaller.
            ///

            bsl::expects(nullptr != file);
            validate_elf64_ehdr(file);

            auto const phdrtab{get_phdrtab(file)};
            for (bsl::safe_idx mut_i{}; mut_i < phdrtab.size(); ++mut_i) {
                auto const *const phdr{phdrtab.at_if(mut_i)};

                switch (phdr->p_type) {
                    case bfelf::PT_LOAD.get(): {
                        validate_pt_load(phdr);
                        break;
                    }

                    case bfelf::PT_GNU_STACK.get(): {
                        validate_pt_gnu_stack(phdr);
                        break;
                    }

                    case bfelf::PT_TLS.get(): {
                        validate_pt_tls(phdr);
                        break;
                    }

                    default: {
                        break;
                    }
                }
            }
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
            bsl::safe_idx const &offset) noexcept -> page_4k_t *
        {
            page_4k_t *pmut_mut_page{};

            /// NOTE:
            /// - The validation code above ensures that phdr->p_vaddr +
            ///   the offset will never overflow, which is why this is
            ///   marked as checked.
            ///

            auto const virt{(phdr->p_vaddr + bsl::to_umx(offset)).checked()};
            if ((phdr->p_flags & bfelf::PF_X).is_pos()) {
                pmut_mut_page =
                    mut_rpt.allocate_page<page_4k_t>(mut_tls, mut_page_pool, virt, MAP_PAGE_RE);
            }
            else {
                pmut_mut_page =
                    mut_rpt.allocate_page<page_4k_t>(mut_tls, mut_page_pool, virt, MAP_PAGE_RW);
            }

            return pmut_mut_page;
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
            constexpr auto inc{bsl::to_idx(HYPERVISOR_PAGE_SIZE)};
            bsl::span const segment{phdr->p_offset, bsl::to_umx(phdr->p_filesz)};

            for (bsl::safe_idx mut_i{}; mut_i < phdr->p_memsz; mut_i += inc) {

                auto *const pmut_page{
                    allocate_page_for_add_segment(mut_tls, mut_page_pool, mut_rpt, phdr, mut_i)};

                if (bsl::unlikely(nullptr == pmut_page)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                /// NOTE:
                /// - Due to the BSS section, the memsz might not actually
                ///   be the same size as the filesz. For this reason, we
                ///   need to keep allocating pages, but might not want to
                ///   copy these pages.
                /// - The subspan figures this out for us. Once the file has
                ///   been completely copies, the subspan will start
                ///   returning an empty subspan, telling us to stop copying.
                ///

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
        ///   @param file the ELF file for this ext_t
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        add_segments(
            tls_t &mut_tls,
            page_pool_t &mut_page_pool,
            root_page_table_t &mut_rpt,
            loader::ext_elf_file_t const *const file) noexcept -> bsl::errc_type
        {
            auto mut_tls_vaddr{bsl::safe_u64::max_value()};

            auto const phdrtab{get_phdrtab(file)};
            for (bsl::safe_idx mut_i{}; mut_i < phdrtab.size(); ++mut_i) {
                auto const *const phdr{phdrtab.at_if(mut_i)};

                if (bfelf::PT_TLS == phdr->p_type) {
                    mut_tls_vaddr = bsl::to_u64(phdr->p_vaddr);
                    break;
                }

                bsl::touch();
            }

            for (bsl::safe_idx mut_i{}; mut_i < phdrtab.size(); ++mut_i) {
                auto const *const phdr{phdrtab.at_if(mut_i)};

                if (bfelf::PT_LOAD != phdr->p_type) {
                    continue;
                }

                /// NOTE:
                /// - Sometimes, you can end up with a PT_LOAD segment that
                ///   is actually the TLS. It will have an alignment that
                ///   is not supported as well. We need to skip these.
                ///

                if (phdr->p_vaddr == mut_tls_vaddr) {
                    continue;
                }

                auto const ret{add_segment(mut_tls, mut_page_pool, mut_rpt, phdr)};
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
            bsl::safe_u64 const &addr) noexcept -> bsl::errc_type
        {
            constexpr auto size{HYPERVISOR_EXT_STACK_SIZE};
            for (bsl::safe_idx mut_i{}; mut_i < size; mut_i += bsl::to_idx(HYPERVISOR_PAGE_SIZE)) {
                auto const virt{(addr + bsl::to_u64(mut_i)).checked()};

                /// NOTE:
                /// - The virtual address provided to allocate_page cannot
                ///   overflow because add_stacks ensures that this is not
                ///   possible, which is why it is marked as checked.
                ///

                auto const *const page{
                    mut_rpt.allocate_page<page_4k_t>(mut_tls, mut_page_pool, virt, MAP_PAGE_RW)};

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
            constexpr auto stack_addr{HYPERVISOR_EXT_STACK_ADDR};
            constexpr auto stack_size{HYPERVISOR_EXT_STACK_SIZE};

            for (bsl::safe_idx mut_i{}; mut_i < bsl::to_idx(mut_tls.online_pps); ++mut_i) {
                auto const offs{(stack_size + HYPERVISOR_PAGE_SIZE) * bsl::to_u64(mut_i)};
                auto const addr{(stack_addr + offs).checked()};

                /// NOTE:
                /// - CMake is responsible for ensuring that the values for
                ///   stack_addr and stack_size make sense. The only way the
                ///   the math above could overflow is if the provided online
                ///   PPs is invalid while at the same time CMake was
                ///   configured with values that could result in overflow.
                ///   This is considered extremely unlikely and therefore
                ///   undefined, which is why addr is marked as checked.
                ///

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
        ///   @brief Adds an exteneion's fail stack for a specific PP to the
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
        add_fail_stack(
            tls_t &mut_tls,
            page_pool_t &mut_page_pool,
            root_page_table_t &mut_rpt,
            bsl::safe_u64 const &addr) noexcept -> bsl::errc_type
        {
            constexpr auto size{HYPERVISOR_EXT_FAIL_STACK_SIZE};
            for (bsl::safe_idx mut_i{}; mut_i < size; mut_i += bsl::to_idx(HYPERVISOR_PAGE_SIZE)) {
                auto const virt{(addr + bsl::to_u64(mut_i)).checked()};

                /// NOTE:
                /// - The virtual address provided to allocate_page cannot
                ///   overflow because add_fail_stacks ensures that this is not
                ///   possible, which is why it is marked as checked.
                ///

                auto const *const page{
                    mut_rpt.allocate_page<page_4k_t>(mut_tls, mut_page_pool, virt, MAP_PAGE_RW)};

                if (bsl::unlikely(nullptr == page)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds the exteneion's fail stacks to the provided
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
        add_fail_stacks(
            tls_t &mut_tls, page_pool_t &mut_page_pool, root_page_table_t &mut_rpt) noexcept
            -> bsl::errc_type
        {
            constexpr auto stack_addr{HYPERVISOR_EXT_FAIL_STACK_ADDR};
            constexpr auto stack_size{HYPERVISOR_EXT_FAIL_STACK_SIZE};

            for (bsl::safe_idx mut_i{}; mut_i < bsl::to_idx(mut_tls.online_pps); ++mut_i) {
                auto const offs{(stack_size + HYPERVISOR_PAGE_SIZE) * bsl::to_u64(mut_i)};
                auto const addr{(stack_addr + offs).checked()};

                /// NOTE:
                /// - CMake is responsible for ensuring that the values for
                ///   stack_addr and stack_size make sense. The only way the
                ///   the math above could overflow is if the provided online
                ///   PPs is invalid while at the same time CMake was
                ///   configured with values that could result in overflow.
                ///   This is considered extremely unlikely and therefore
                ///   undefined, which is why addr is marked as checked.
                ///

                auto const ret{this->add_fail_stack(mut_tls, mut_page_pool, mut_rpt, addr)};
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
            bsl::safe_u64 const &addr,
            bfelf::elf64_phdr_t const *const phdr) noexcept -> bsl::errc_type
        {
            auto *const pmut_page{
                mut_rpt.allocate_page<page_4k_t>(mut_tls, mut_page_pool, addr, MAP_PAGE_RW)};

            if (bsl::unlikely(nullptr == pmut_page)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            /// NOTE:
            /// - Since the validation code above ensures that the TLB block
            ///   in the phdr is no larger than a page, dst_idx cannot
            ///   underflow, which is why it is marked as checked().
            ///

            bsl::span const src{phdr->p_offset, bsl::to_umx(phdr->p_filesz)};

            /// NOTE:
            /// - The dst_idx is needed because the TLS data is in a sense,
            ///   right justified. Meaning, we allocate a full page, but if
            ///   the extension only uses 100 bytes, the data starts at the
            ///   last 100 bytes of the page.
            ///

            auto const dst_idx{bsl::to_idx((HYPERVISOR_PAGE_SIZE - phdr->p_memsz).checked())};
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
            bsl::safe_u64 const &addr) noexcept -> bsl::errc_type
        {
            auto *const pmut_page{
                mut_rpt.allocate_page<ext_tcb_t>(mut_tls, mut_page_pool, addr, MAP_PAGE_RW)};

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
        ///   @param file the ELF file that contains the TLS info
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        add_tls_blocks(
            tls_t &mut_tls,
            page_pool_t &mut_page_pool,
            root_page_table_t &mut_rpt,
            loader::ext_elf_file_t const *const file) noexcept -> bsl::errc_type
        {
            bfelf::elf64_phdr_t const *mut_phdr{};
            constexpr auto tls_addr{HYPERVISOR_EXT_TLS_ADDR};
            constexpr auto tls_size{HYPERVISOR_EXT_TLS_SIZE};

            for (bsl::safe_idx mut_i{}; mut_i < bsl::to_umx(mut_tls.online_pps); ++mut_i) {
                auto const offs{(tls_size + HYPERVISOR_PAGE_SIZE) * bsl::to_u64(mut_i)};
                auto const addr{(tls_addr + offs + HYPERVISOR_PAGE_SIZE).checked()};

                /// NOTE:
                /// - CMake is responsible for ensuring that the values for
                ///   tls_addr and tls_size make sense. The only way the
                ///   the math above could overflow is if the provided online
                ///   PPs is invalid while at the same time CMake was
                ///   configured with values that could result in overflow.
                ///   This is considered extremely unlikely and therefore
                ///   undefined, which is why addr is marked as checked.
                ///

                auto const ret{this->add_tcb(mut_tls, mut_page_pool, mut_rpt, addr)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }

            auto const phdrtab{get_phdrtab(file)};
            for (bsl::safe_idx mut_i{}; mut_i < phdrtab.size(); ++mut_i) {
                auto const *const phdr{phdrtab.at_if(mut_i)};

                if (bfelf::PT_TLS == phdr->p_type) {
                    mut_phdr = phdr;
                    break;
                }

                bsl::touch();
            }

            if (nullptr == mut_phdr) {
                return bsl::errc_success;
            }

            for (bsl::safe_idx mut_i{}; mut_i < bsl::to_umx(mut_tls.online_pps); ++mut_i) {
                auto const offs{(tls_size + HYPERVISOR_PAGE_SIZE) * bsl::to_u64(mut_i)};
                auto const addr{(tls_addr + offs).checked()};

                /// NOTE:
                /// - CMake is responsible for ensuring that the values for
                ///   tls_addr and tls_size make sense. The only way the
                ///   the math above could overflow is if the provided online
                ///   PPs is invalid while at the same time CMake was
                ///   configured with values that could result in overflow.
                ///   This is considered extremely unlikely and therefore
                ///   undefined, which is why addr is marked as checked.
                ///

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
        ///   @param file the ELF file that contains the segment and TLS
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
            loader::ext_elf_file_t const *const file) noexcept -> bsl::errc_type
        {
            bsl::errc_type mut_ret{};

            mut_ret = mut_rpt.initialize(mut_tls, mut_page_pool);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            bsl::finally mut_release_on_error{
                [&mut_tls, &mut_rpt, &mut_page_pool]() noexcept -> void {
                    mut_rpt.release(mut_tls, mut_page_pool);
                }};

            mut_rpt.add_tables(mut_tls, system_rpt);

            mut_ret = this->add_segments(mut_tls, mut_page_pool, mut_rpt, file);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            mut_ret = this->add_stacks(mut_tls, mut_page_pool, mut_rpt);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            mut_ret = this->add_fail_stacks(mut_tls, mut_page_pool, mut_rpt);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            mut_ret = this->add_tls_blocks(mut_tls, mut_page_pool, mut_rpt, file);
            if (bsl::unlikely(!mut_ret)) {
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
        ///   @param pmut_rpt the root page table to initialize
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize_direct_map_rpt(
            tls_t &mut_tls, page_pool_t &mut_page_pool, root_page_table_t *const pmut_rpt) noexcept
            -> bsl::errc_type
        {
            auto const ret{pmut_rpt->initialize(mut_tls, mut_page_pool)};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            pmut_rpt->add_tables(mut_tls, m_main_rpt);
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Makes sure that all m_main_rpt aliases are updated
        ///     in all of the direct maps. This ensures that any allocations
        ///     are mapped into all VMs.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///
        constexpr void
        update_direct_map_rpts(tls_t &mut_tls) noexcept
        {
            for (auto &mut_rpt : m_direct_map_rpts) {
                if (!mut_rpt.is_initialized()) {
                    continue;
                }

                mut_rpt.add_tables(mut_tls, m_main_rpt);
            }
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
            bsl::safe_u64 const &ip,
            bsl::safe_u64 const &arg0 = {},
            bsl::safe_u64 const &arg1 = {}) noexcept -> bsl::errc_type
        {
            bsl::expects(ip.is_valid_and_checked());
            bsl::expects(ip.is_pos());
            bsl::expects(arg0.is_valid_and_checked());
            bsl::expects(arg1.is_valid_and_checked());

            auto *const pmut_rpt{m_direct_map_rpts.at_if(bsl::to_idx(mut_tls.active_vmid))};
            bsl::expects(nullptr != pmut_rpt);

            if (pmut_rpt->is_inactive(mut_tls)) {
                pmut_rpt->activate(mut_tls, mut_intrinsic);
            }
            else {
                bsl::touch();
            }

            if (mut_tls.ext != this) {
                mut_tls.ext = this;
                mut_tls.active_extid = this->id().get();
            }
            else {
                bsl::touch();
            }

            if (ip == m_fail_ip) {
                return call_ext(ip.get(), mut_tls.ext_fail_sp, arg0.get(), arg1.get());
            }

            return call_ext(ip.get(), mut_tls.sp, arg0.get(), arg1.get());
        }

    public:
        /// <!-- description -->
        ///   @brief Initializes this ext_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param i the ID for this ext_t
        ///   @param file the ELF file for this ext_t
        ///   @param system_rpt the system RPT provided by the loader
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(
            tls_t &mut_tls,
            page_pool_t &mut_page_pool,
            bsl::safe_u16 const &i,
            loader::ext_elf_file_t const *const file,
            root_page_table_t const &system_rpt) noexcept -> bsl::errc_type
        {
            bsl::expects(i.is_valid_and_checked());
            bsl::expects(i != syscall::BF_INVALID_ID);
            bsl::expects(nullptr != file);

            validate(file);
            m_entry_ip = file->e_entry;

            auto const ret{
                this->initialize_rpt(mut_tls, mut_page_pool, m_main_rpt, system_rpt, file)};

            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            m_id = ~i;
            m_handle = syscall::BF_INVALID_HANDLE;
            return ret;
        }

        /// <!-- description -->
        ///   @brief Release the ext_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param mut_huge_pool the huge_pool_t to use
        ///
        constexpr void
        release(tls_t &mut_tls, page_pool_t &mut_page_pool, huge_pool_t &mut_huge_pool) noexcept
        {
            for (bsl::safe_idx mut_i; mut_i < m_huge_allocs_idx; ++mut_i) {
                auto *const pmut_huge{m_huge_allocs.at_if(mut_i)};

                auto const huge_phys{mut_huge_pool.virt_to_phys(pmut_huge->data())};
                bsl::expects(huge_phys.is_valid_and_checked());
                bsl::expects(huge_phys.is_pos());

                auto const huge_virt{(HYPERVISOR_EXT_HUGE_POOL_ADDR + huge_phys).checked()};
                bsl::expects(huge_virt.is_valid_and_checked());
                bsl::expects(huge_virt.is_pos());

                bsl::discard(m_main_rpt.unmap(mut_tls, mut_page_pool, huge_virt));
                mut_huge_pool.deallocate(mut_tls, *pmut_huge);
            }

            m_huge_allocs_idx = {};
            for (auto &mut_elem : m_huge_allocs) {
                mut_elem = {};
            }

            m_fail_ip = {};
            m_vmexit_ip = {};
            m_bootstrap_ip = {};
            m_entry_ip = {};

            for (auto &mut_rpt : m_direct_map_rpts) {
                mut_rpt.release(mut_tls, mut_page_pool);
            }

            m_main_rpt.release(mut_tls, mut_page_pool);

            m_is_executing_fail = {};
            m_has_executed_start = {};
            m_handle = {};
            m_id = {};
        }

        /// <!-- description -->
        ///   @brief Returns the ID of this ext_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of this ext_t
        ///
        [[nodiscard]] constexpr auto
        id() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_id.is_valid_and_checked());
            return ~m_id;
        }

        /// <!-- description -->
        ///   @brief Returns the bootstrap IP for this extension.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the bootstrap IP for this extension.
        ///
        [[nodiscard]] constexpr auto
        bootstrap_ip() const noexcept -> bsl::safe_u64 const &
        {
            bsl::ensures(m_bootstrap_ip.is_valid_and_checked());
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
        set_bootstrap_ip(bsl::safe_u64 const &ip) noexcept
        {
            bsl::expects(ip.is_valid_and_checked());
            bsl::expects(ip.is_pos());

            m_bootstrap_ip = ip;
        }

        /// <!-- description -->
        ///   @brief Returns the VMExit IP for this extension.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the VMExit IP for this extension.
        ///
        [[nodiscard]] constexpr auto
        vmexit_ip() const noexcept -> bsl::safe_u64 const &
        {
            bsl::ensures(m_vmexit_ip.is_valid_and_checked());
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
        set_vmexit_ip(bsl::safe_u64 const &ip) noexcept
        {
            bsl::expects(ip.is_valid_and_checked());
            bsl::expects(ip.is_pos());

            m_vmexit_ip = ip;
        }

        /// <!-- description -->
        ///   @brief Returns the fast fail IP for this extension.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the fast fail IP for this extension.
        ///
        [[nodiscard]] constexpr auto
        fail_ip() const noexcept -> bsl::safe_u64 const &
        {
            bsl::ensures(m_fail_ip.is_valid_and_checked());
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
        set_fail_ip(bsl::safe_u64 const &ip) noexcept
        {
            bsl::expects(ip.is_valid_and_checked());
            bsl::expects(ip.is_pos());

            m_fail_ip = ip;
        }

        /// <!-- description -->
        ///   @brief Opens a handle and returns the resulting handle
        ///
        /// <!-- inputs/outputs -->
        ///   @return Opens a handle and returns the resulting handle
        ///
        [[nodiscard]] constexpr auto
        open_handle() noexcept -> bsl::safe_u64
        {
            if (bsl::unlikely(m_handle.is_zero())) {
                bsl::error() << "handle already opened\n" << bsl::here();
                return bsl::safe_u64::failure();
            }

            m_handle = {};
            return this->handle();
        }

        /// <!-- description -->
        ///   @brief Closes a previously opened handle
        ///
        constexpr void
        close_handle() noexcept
        {
            m_handle = syscall::BF_INVALID_HANDLE;
        }

        /// <!-- description -->
        ///   @brief Returns true if provided handle is valid
        ///
        /// <!-- inputs/outputs -->
        ///   @param hndl the handle to verify
        ///   @return Returns true if provided handle is valid
        ///
        [[nodiscard]] constexpr auto
        is_handle_valid(bsl::safe_u64 const &hndl) const noexcept -> bool
        {
            bsl::expects(hndl.is_valid_and_checked());
            return hndl == m_handle;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of this ext_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of this ext_t
        ///
        [[nodiscard]] constexpr auto
        handle() const noexcept -> bsl::safe_u64
        {
            bsl::ensures(m_handle.is_valid_and_checked());
            return m_handle;
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
            return m_has_executed_start;
        }

        /// <!-- description -->
        ///   @brief Returns true if the extension's main function is
        ///     executing the fail_entry().
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the extension's main function is
        ///     executing the fail_entry().
        ///
        [[nodiscard]] constexpr auto
        is_executing_fail() const noexcept -> bool
        {
            return m_is_executing_fail;
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
            auto const page{m_main_rpt.allocate_page<>(mut_tls, mut_page_pool)};
            if (bsl::unlikely(page.virt.is_invalid())) {
                bsl::print<bsl::V>() << bsl::here();
                return {bsl::safe_u64::failure(), bsl::safe_u64::failure()};
            }

            this->update_direct_map_rpts(mut_tls);
            return page;
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
            bsl::safe_umx const &size) noexcept -> alloc_huge_t
        {
            bsl::expects(size.is_valid_and_checked());
            bsl::expects(size.is_pos());

            if (bsl::unlikely(m_huge_allocs_idx >= HYPERVISOR_MAX_HUGE_ALLOCS)) {
                bsl::error() << "ext out of huge allocation slots\n" << bsl::endl;
                return {bsl::safe_u64::failure(), bsl::safe_u64::failure()};
            }

            auto [mut_bytes, mut_pages]{size_to_page_aligned_bytes(size)};
            if (bsl::unlikely(mut_bytes.is_poisoned())) {
                bsl::print<bsl::V>() << bsl::here();
                return {bsl::safe_u64::failure(), bsl::safe_u64::failure()};
            }

            auto mut_huge{mut_huge_pool.allocate(mut_tls, mut_pages)};
            if (bsl::unlikely(mut_huge.is_invalid())) {
                bsl::print<bsl::V>() << bsl::here();
                return {bsl::safe_u64::failure(), bsl::safe_u64::failure()};
            }

            /// TODO:
            /// - We really should register the allocation at the end of this
            ///   function, and on failure, we would just call free_huge()
            ///   so that all of the memory can be unmapped and deallocated
            ///   there. By registering here, if the map() below fails, we
            ///   are not leaking memory, but the allocation is lost and can
            ///   never be used again.
            ///
            /// - For now this works because if the allocation fails, there
            ///   likely is no way to recover anyways as this is such a
            ///   limited resource, but if free_huge() is ever implemented,
            ///   this should be changed to "undo" what was done here so
            ///   that the huge allocation can be used in the future.
            ///

            *m_huge_allocs.at_if(m_huge_allocs_idx) = mut_huge;
            ++m_huge_allocs_idx;

            auto const huge_phys{mut_huge_pool.virt_to_phys(mut_huge.data())};
            bsl::expects(huge_phys.is_valid_and_checked());
            bsl::expects(huge_phys.is_pos());

            auto const huge_virt{(HYPERVISOR_EXT_HUGE_POOL_ADDR + huge_phys).checked()};
            bsl::expects(huge_virt.is_valid_and_checked());
            bsl::expects(huge_virt.is_pos());

            /// NOTE:
            /// - Huge allocations come from the kernel's direct map, which
            ///   is the same size as the extension's direct map, something
            ///   that is validated by CMake. As a result, the virtual and
            ///   physical addresses below can never overflow which is why
            ///   they are marked as checked().
            ///

            constexpr auto inc{bsl::to_idx(HYPERVISOR_PAGE_SIZE)};
            for (bsl::safe_idx mut_i{}; mut_i < mut_bytes; mut_i += inc) {
                auto const page_virt{(huge_virt + bsl::to_u64(mut_i)).checked()};
                auto const page_phys{(huge_phys + bsl::to_u64(mut_i)).checked()};

                auto const ret{m_main_rpt.map(
                    mut_tls, mut_page_pool, page_virt, page_phys, MAP_PAGE_RW, true)};

                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return {bsl::safe_u64::failure(), bsl::safe_u64::failure()};
                }

                bsl::touch();
            }

            this->update_direct_map_rpts(mut_tls);
            return {huge_virt, huge_phys};
        }

        /// <!-- description -->
        ///   @brief Maps a page into the direct map portion of the requested
        ///     VM's direct map RPT given a physical address to map.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param vmid the ID of the VM to map page_phys to
        ///   @param page_phys the physical address to map
        ///   @return Returns the virtual address the physical address was
        ///     mapped to in the direct map. On failure returns
        ///     bsl::safe_u64::failure().
        ///
        [[nodiscard]] constexpr auto
        map_page_direct(
            tls_t &mut_tls,
            page_pool_t &mut_page_pool,
            bsl::safe_u16 const &vmid,
            bsl::safe_u64 const &page_phys) noexcept -> bsl::safe_u64
        {
            constexpr auto min_addr{HYPERVISOR_EXT_DIRECT_MAP_ADDR};

            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(bsl::to_umx(vmid) < m_direct_map_rpts.size());
            bsl::expects(page_phys.is_valid_and_checked());
            bsl::expects(page_phys.is_pos());
            bsl::expects(page_phys < min_addr);

            /// NOTE:
            /// - CMake ensures that the addr and size make sense which is why
            ///   the following is marked as checked.
            ///

            auto const page_virt{(page_phys + min_addr).checked()};
            bsl::expects(page_virt.is_valid_and_checked());
            bsl::expects(page_virt.is_pos());

            auto *const pmut_direct_map_rpt{m_direct_map_rpts.at_if(bsl::to_idx(vmid))};
            bsl::expects(nullptr != pmut_direct_map_rpt);

            auto const ret{pmut_direct_map_rpt->map(
                mut_tls, mut_page_pool, page_virt, page_phys, MAP_PAGE_RW)};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_u64::failure();
            }

            return page_virt;
        }

        /// <!-- description -->
        ///   @brief Unmaps a page from the direct map portion of the requested
        ///     VM's direct map RPT given a virtual address to unmap.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vmid the ID of the VM to unmap page_virt to
        ///   @param page_virt the virtual address to map
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        unmap_page_direct(
            tls_t &mut_tls,
            page_pool_t &mut_page_pool,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &vmid,
            bsl::safe_u64 const &page_virt) noexcept -> bsl::errc_type
        {
            constexpr auto min_addr{HYPERVISOR_EXT_DIRECT_MAP_ADDR};
            constexpr auto max_addr{(min_addr + HYPERVISOR_EXT_DIRECT_MAP_SIZE).checked()};

            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(bsl::to_umx(vmid) < m_direct_map_rpts.size());
            bsl::expects(page_virt.is_valid_and_checked());
            bsl::expects(page_virt.is_pos());
            bsl::expects(page_virt >= min_addr);
            bsl::expects(page_virt <= max_addr);

            auto *const pmut_direct_map_rpt{m_direct_map_rpts.at_if(bsl::to_idx(vmid))};
            bsl::expects(nullptr != pmut_direct_map_rpt);

            auto const ret{pmut_direct_map_rpt->unmap(mut_tls, mut_page_pool, page_virt)};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            intrinsic.tlb_flush(page_virt);
            return ret;
        }

        /// <!-- description -->
        ///   @brief Tells the extension that a VM was created so that it
        ///     can initialize it's VM specific resources.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param vmid the ID of the VM that was created.
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        signal_vm_created(
            tls_t &mut_tls, page_pool_t &mut_page_pool, bsl::safe_u16 const &vmid) noexcept
            -> bsl::errc_type
        {
            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(bsl::to_umx(vmid) < m_direct_map_rpts.size());

            auto const ret{this->initialize_direct_map_rpt(
                mut_tls, mut_page_pool, m_direct_map_rpts.at_if(bsl::to_idx(vmid)))};

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
        ///   @param vmid the ID of the VM that was destroyed.
        ///
        constexpr void
        signal_vm_destroyed(
            tls_t &mut_tls, page_pool_t &mut_page_pool, bsl::safe_u16 const &vmid) noexcept
        {
            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(bsl::to_umx(vmid) < m_direct_map_rpts.size());

            m_direct_map_rpts.at_if(bsl::to_idx(vmid))->release(mut_tls, mut_page_pool);
        }

        /// <!-- description -->
        ///   @brief Tells the extension that the requested VM was set to
        ///     active and therefore it's memory map should change on this PP.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsic_t to use
        ///   @param vmid the ID of the VM that was created.
        ///
        constexpr void
        signal_vm_active(
            tls_t &mut_tls, intrinsic_t &mut_intrinsic, bsl::safe_u16 const &vmid) noexcept
        {
            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(bsl::to_umx(mut_tls.active_vmid) < m_direct_map_rpts.size());

            auto *const pmut_rpt{m_direct_map_rpts.at_if(bsl::to_idx(mut_tls.active_vmid))};
            bsl::expects(nullptr != pmut_rpt);

            pmut_rpt->activate(mut_tls, mut_intrinsic);
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
            auto const arg{bsl::to_u64(syscall::BF_ALL_SPECS_SUPPORTED_VAL)};
            auto const ret{this->execute(mut_tls, mut_intrinsic, m_entry_ip, arg)};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            m_has_executed_start = true;
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
            if (bsl::unlikely(m_bootstrap_ip.is_zero())) {
                bsl::error() << "a bootstrap handler was not registered for ext "    // --
                             << bsl::hex(this->id())                                 // --
                             << bsl::endl                                            // --
                             << bsl::here();                                         // --

                return bsl::errc_failure;
            }

            auto const arg{bsl::to_u64(mut_tls.ppid)};
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
            tls_t &mut_tls, intrinsic_t &mut_intrinsic, bsl::safe_u64 const &exit_reason) noexcept
            -> bsl::errc_type
        {
            auto const arg0{bsl::to_u64(mut_tls.active_vsid)};
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
        ///   @param errc the reason for the failure, which is CPU
        ///     specific. On x86, this is a combination of the exception
        ///     vector and error code.
        ///   @param addr contains a faulting address if the fail reason
        ///     is associated with an error that involves a faulting address (
        ///     for example like a page fault). Otherwise, the value of this
        ///     input is undefined.
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        fail(
            tls_t &mut_tls,
            intrinsic_t &mut_intrinsic,
            bsl::safe_u64 const &errc,
            bsl::safe_u64 const &addr) noexcept -> bsl::errc_type
        {
            m_is_executing_fail = true;
            auto const ret{this->execute(mut_tls, mut_intrinsic, m_fail_ip, errc, addr)};
            m_is_executing_fail = {};

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
        ///
        constexpr void
        dump(tls_t const &tls) const noexcept
        {
            if constexpr (BSL_DEBUG_LEVEL == bsl::CRITICAL_ONLY) {
                return;
            }

            bsl::print() << bsl::mag << "ext [";
            bsl::print() << bsl::rst << bsl::hex(this->id());
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
            if (m_has_executed_start) {
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
            if (tls.active_extid == this->id()) {
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
            if (m_bootstrap_ip.is_pos()) {
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
            if (m_vmexit_ip.is_pos()) {
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
            if (m_fail_ip.is_pos()) {
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
            if (m_handle.is_zero()) {
                bsl::print() << bsl::rst << "      " << bsl::hex(m_handle) << "       ";
            }
            else {
                bsl::print() << bsl::red << bsl::fmt{"^19s", "not opened "};
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Footer
            ///

            bsl::print() << bsl::ylw << "+------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;
        }
    };
}

#endif
