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

#include "../../../src/ext_t.hpp"

#include <basic_alloc_huge_t.hpp>
#include <basic_alloc_page_t.hpp>
#include <basic_root_page_table_t.hpp>
#include <bf_constants.hpp>
#include <bfelf/elf64_ehdr_t.hpp>
#include <bfelf/elf64_phdr_t.hpp>
#include <huge_pool_t.hpp>
#include <intrinsic_t.hpp>
#include <mk_args_t.hpp>
#include <page_pool_t.hpp>
#include <root_page_table_t.hpp>
#include <tls_t.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/span.hpp>
#include <bsl/ut.hpp>

namespace mk
{
    /// @brief defines the total number of program headers in our ELF file
    constexpr auto PHNUM{7_u64};
    /// @brief defines the total number of online PPs in our unittests
    constexpr auto NUM_ONLINE_PPS{2_u16};

    /// @brief defines the program header table type
    using phdr_table_t = bsl::array<bfelf::elf64_phdr_t, PHNUM.get()>;

    /// @brief defines the total size of our ELF file
    constexpr auto ELF_FILE_BUF_SIZE{0x200000_umx};
    /// @brief defines type used to store the actual bits for an ELF file
    using elf_file_buf_t = bsl::span<bsl::uint8 const>;

    /// @brief defines the index of our RE PT_LOAD segment
    constexpr auto PHDR_PT_LOAD_RE_IDX{0_idx};
    /// @brief defines the index of our RO PT_LOAD segment
    constexpr auto PHDR_PT_LOAD_RO_IDX{1_idx};
    /// @brief defines the index of our RW PT_LOAD segment
    constexpr auto PHDR_PT_LOAD_RW_IDX{2_idx};
    /// @brief defines the index of our TLS PT_LOAD segment
    constexpr auto PHDR_PT_LOAD_TLS_IDX{3_idx};
    /// @brief defines the index of our PT_TLS segment
    constexpr auto PHDR_PT_TLS_IDX{4_idx};
    /// @brief defines the index of our GNU_STACK segment
    constexpr auto PHDR_PT_GNU_STACK_IDX{5_idx};

    /// @brief defines the virtual address of our RE PT_LOAD segment
    constexpr auto PT_LOAD_RE_VADDR{0x0000328000000000_u64};
    /// @brief defines the physical address of our RE PT_LOAD segment
    constexpr auto PT_LOAD_RE_PADDR{0x0000328000000000_u64};
    /// @brief defines the file size of our RE PT_LOAD segment
    constexpr auto PT_LOAD_RE_FILSZ{0x2000_u64};
    /// @brief defines the memory size of our RE PT_LOAD segment
    constexpr auto PT_LOAD_RE_MEMSZ{0x3000_u64};
    /// @brief defines the virtual address of our RO PT_LOAD segment
    constexpr auto PT_LOAD_RO_VADDR{0x0000328000003000_u64};
    /// @brief defines the physical address of our RO PT_LOAD segment
    constexpr auto PT_LOAD_RO_PADDR{0x0000328000003000_u64};
    /// @brief defines the file size of our RO PT_LOAD segment
    constexpr auto PT_LOAD_RO_FILSZ{0x2000_u64};
    /// @brief defines the memory size of our RO PT_LOAD segment
    constexpr auto PT_LOAD_RO_MEMSZ{0x3000_u64};
    /// @brief defines the virtual address of our RW PT_LOAD segment
    constexpr auto PT_LOAD_RW_VADDR{0x0000328000006000_u64};
    /// @brief defines the physical address of our RW PT_LOAD segment
    constexpr auto PT_LOAD_RW_PADDR{0x0000328000006000_u64};
    /// @brief defines the file size of our RW PT_LOAD segment
    constexpr auto PT_LOAD_RW_FILSZ{0x2000_u64};
    /// @brief defines the memory size of our RW PT_LOAD segment
    constexpr auto PT_LOAD_RW_MEMSZ{0x3000_u64};
    /// @brief defines the virtual address of our TLS PT_LOAD segment
    constexpr auto PT_LOAD_TLS_VADDR{0x0000328000010000_u64};
    /// @brief defines the physical address of our TLS PT_LOAD segment
    constexpr auto PT_LOAD_TLS_PADDR{0x0000328000010000_u64};
    /// @brief defines the file size of our TLS PT_LOAD segment
    constexpr auto PT_LOAD_TLS_FILSZ{0x10_u64};
    /// @brief defines the memory size of our TLS PT_LOAD segment
    constexpr auto PT_LOAD_TLS_MEMSZ{0x28_u64};
    /// @brief defines the virtual address of our PT_TLS segment
    constexpr auto PT_TLS_VADDR{0x0000328000010000_u64};
    /// @brief defines the physical address of our PT_TLS segment
    constexpr auto PT_TLS_PADDR{0x0000328000010000_u64};
    /// @brief defines the file size of our PT_TLS segment
    constexpr auto PT_TLS_FILSZ{0x10_u64};
    /// @brief defines the memory size of our PT_TLS segment
    constexpr auto PT_TLS_MEMSZ{0x28_u64};
    /// @brief defines the virtual address of our GNU_STACK segment
    constexpr auto PT_GNU_STACK_VADDR{0x0_u64};
    /// @brief defines the physical address of our GNU_STACK segment
    constexpr auto PT_GNU_STACK_PADDR{0x0_u64};
    /// @brief defines the file size of our GNU_STACK segment
    constexpr auto PT_GNU_STACK_FILSZ{0x0_u64};
    /// @brief defines the memory size of our GNU_STACK segment
    constexpr auto PT_GNU_STACK_MEMSZ{0x0_u64};

    /// <!-- description -->
    ///   @brief Returns an allocated and initialized ELF file buffer for use
    ///     during testing.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns an allocated and initialized ELF file buffer for use
    ///     during testing.
    ///
    [[nodiscard]] constexpr auto
    get_elf_file_buf() noexcept -> elf_file_buf_t
    {
        return {new bsl::uint8[ELF_FILE_BUF_SIZE.get()](), ELF_FILE_BUF_SIZE};
    }

    /// <!-- description -->
    ///   @brief Deletes the provided ELF file buffer.
    ///
    /// <!-- inputs/outputs -->
    ///   @param elf_file_buf the ELF file buffer to delete
    ///
    constexpr void
    clr_elf_file_buf(elf_file_buf_t const &elf_file_buf) noexcept
    {
        delete[] elf_file_buf.data();    // NOLINT // GRCOV_EXCLUDE_BR
    }

    /// <!-- description -->
    ///   @brief Loads the initial state of the program header table.
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_phdr_table the program header table to initialize
    ///   @param elf_file_buf the ELF file to use
    ///
    constexpr void
    load_phdr_table(phdr_table_t &mut_phdr_table, elf_file_buf_t const &elf_file_buf) noexcept
    {
        mut_phdr_table.at_if(PHDR_PT_LOAD_RE_IDX)->p_type = bfelf::PT_LOAD.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RE_IDX)->p_flags = (bfelf::PF_X | bfelf::PF_R).get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RE_IDX)->p_offset = elf_file_buf.data();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RE_IDX)->p_vaddr = PT_LOAD_RE_VADDR.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RE_IDX)->p_paddr = PT_LOAD_RE_PADDR.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RE_IDX)->p_filesz = PT_LOAD_RE_FILSZ.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RE_IDX)->p_memsz = PT_LOAD_RE_MEMSZ.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RE_IDX)->p_align = HYPERVISOR_PAGE_SIZE.get();

        mut_phdr_table.at_if(PHDR_PT_LOAD_RO_IDX)->p_type = bfelf::PT_LOAD.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RO_IDX)->p_flags = bfelf::PF_R.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RO_IDX)->p_offset = elf_file_buf.data();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RO_IDX)->p_vaddr = PT_LOAD_RO_VADDR.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RO_IDX)->p_paddr = PT_LOAD_RO_PADDR.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RO_IDX)->p_filesz = PT_LOAD_RO_FILSZ.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RO_IDX)->p_memsz = PT_LOAD_RO_MEMSZ.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RO_IDX)->p_align = HYPERVISOR_PAGE_SIZE.get();

        mut_phdr_table.at_if(PHDR_PT_LOAD_RW_IDX)->p_type = bfelf::PT_LOAD.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RW_IDX)->p_flags = (bfelf::PF_W | bfelf::PF_R).get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RW_IDX)->p_offset = elf_file_buf.data();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RW_IDX)->p_vaddr = PT_LOAD_RW_VADDR.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RW_IDX)->p_paddr = PT_LOAD_RW_PADDR.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RW_IDX)->p_filesz = PT_LOAD_RW_FILSZ.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RW_IDX)->p_memsz = PT_LOAD_RW_MEMSZ.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RW_IDX)->p_align = HYPERVISOR_PAGE_SIZE.get();

        mut_phdr_table.at_if(PHDR_PT_LOAD_TLS_IDX)->p_type = bfelf::PT_LOAD.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_TLS_IDX)->p_flags = (bfelf::PF_W | bfelf::PF_R).get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_TLS_IDX)->p_offset = elf_file_buf.data();
        mut_phdr_table.at_if(PHDR_PT_LOAD_TLS_IDX)->p_vaddr = PT_LOAD_TLS_VADDR.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_TLS_IDX)->p_paddr = PT_LOAD_TLS_PADDR.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_TLS_IDX)->p_filesz = PT_LOAD_TLS_FILSZ.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_TLS_IDX)->p_memsz = PT_LOAD_TLS_MEMSZ.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_TLS_IDX)->p_align = HYPERVISOR_PAGE_SIZE.get();

        mut_phdr_table.at_if(PHDR_PT_TLS_IDX)->p_type = bfelf::PT_TLS.get();
        mut_phdr_table.at_if(PHDR_PT_TLS_IDX)->p_flags = (bfelf::PF_W | bfelf::PF_R).get();
        mut_phdr_table.at_if(PHDR_PT_TLS_IDX)->p_offset = elf_file_buf.data();
        mut_phdr_table.at_if(PHDR_PT_TLS_IDX)->p_vaddr = PT_TLS_VADDR.get();
        mut_phdr_table.at_if(PHDR_PT_TLS_IDX)->p_paddr = PT_TLS_PADDR.get();
        mut_phdr_table.at_if(PHDR_PT_TLS_IDX)->p_filesz = PT_TLS_FILSZ.get();
        mut_phdr_table.at_if(PHDR_PT_TLS_IDX)->p_memsz = PT_TLS_MEMSZ.get();
        mut_phdr_table.at_if(PHDR_PT_TLS_IDX)->p_align = {};

        mut_phdr_table.at_if(PHDR_PT_GNU_STACK_IDX)->p_type = bfelf::PT_GNU_STACK.get();
        mut_phdr_table.at_if(PHDR_PT_GNU_STACK_IDX)->p_flags = (bfelf::PF_W | bfelf::PF_R).get();
        mut_phdr_table.at_if(PHDR_PT_GNU_STACK_IDX)->p_offset = elf_file_buf.data();
        mut_phdr_table.at_if(PHDR_PT_GNU_STACK_IDX)->p_vaddr = PT_GNU_STACK_VADDR.get();
        mut_phdr_table.at_if(PHDR_PT_GNU_STACK_IDX)->p_paddr = PT_GNU_STACK_PADDR.get();
        mut_phdr_table.at_if(PHDR_PT_GNU_STACK_IDX)->p_filesz = PT_GNU_STACK_FILSZ.get();
        mut_phdr_table.at_if(PHDR_PT_GNU_STACK_IDX)->p_memsz = PT_GNU_STACK_MEMSZ.get();
        mut_phdr_table.at_if(PHDR_PT_GNU_STACK_IDX)->p_align = {};
    }

    /// <!-- description -->
    ///   @brief Loads the initial state of the program header table.
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_phdr_table the program header table to initialize
    ///   @param elf_file_buf the ELF file to use
    ///
    constexpr void
    load_phdr_table_without_tls(
        phdr_table_t &mut_phdr_table, elf_file_buf_t const &elf_file_buf) noexcept
    {
        mut_phdr_table.at_if(PHDR_PT_LOAD_RE_IDX)->p_type = bfelf::PT_LOAD.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RE_IDX)->p_flags = (bfelf::PF_X | bfelf::PF_R).get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RE_IDX)->p_offset = elf_file_buf.data();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RE_IDX)->p_vaddr = PT_LOAD_RE_VADDR.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RE_IDX)->p_paddr = PT_LOAD_RE_PADDR.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RE_IDX)->p_filesz = PT_LOAD_RE_FILSZ.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RE_IDX)->p_memsz = PT_LOAD_RE_MEMSZ.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RE_IDX)->p_align = HYPERVISOR_PAGE_SIZE.get();

        mut_phdr_table.at_if(PHDR_PT_LOAD_RO_IDX)->p_type = bfelf::PT_LOAD.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RO_IDX)->p_flags = bfelf::PF_R.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RO_IDX)->p_offset = elf_file_buf.data();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RO_IDX)->p_vaddr = PT_LOAD_RO_VADDR.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RO_IDX)->p_paddr = PT_LOAD_RO_PADDR.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RO_IDX)->p_filesz = PT_LOAD_RO_FILSZ.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RO_IDX)->p_memsz = PT_LOAD_RO_MEMSZ.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RO_IDX)->p_align = HYPERVISOR_PAGE_SIZE.get();

        mut_phdr_table.at_if(PHDR_PT_LOAD_RW_IDX)->p_type = bfelf::PT_LOAD.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RW_IDX)->p_flags = (bfelf::PF_W | bfelf::PF_R).get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RW_IDX)->p_offset = elf_file_buf.data();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RW_IDX)->p_vaddr = PT_LOAD_RW_VADDR.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RW_IDX)->p_paddr = PT_LOAD_RW_PADDR.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RW_IDX)->p_filesz = PT_LOAD_RW_FILSZ.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RW_IDX)->p_memsz = PT_LOAD_RW_MEMSZ.get();
        mut_phdr_table.at_if(PHDR_PT_LOAD_RW_IDX)->p_align = HYPERVISOR_PAGE_SIZE.get();

        mut_phdr_table.at_if(PHDR_PT_GNU_STACK_IDX)->p_type = bfelf::PT_GNU_STACK.get();
        mut_phdr_table.at_if(PHDR_PT_GNU_STACK_IDX)->p_flags = (bfelf::PF_W | bfelf::PF_R).get();
        mut_phdr_table.at_if(PHDR_PT_GNU_STACK_IDX)->p_offset = elf_file_buf.data();
        mut_phdr_table.at_if(PHDR_PT_GNU_STACK_IDX)->p_vaddr = PT_GNU_STACK_VADDR.get();
        mut_phdr_table.at_if(PHDR_PT_GNU_STACK_IDX)->p_paddr = PT_GNU_STACK_PADDR.get();
        mut_phdr_table.at_if(PHDR_PT_GNU_STACK_IDX)->p_filesz = PT_GNU_STACK_FILSZ.get();
        mut_phdr_table.at_if(PHDR_PT_GNU_STACK_IDX)->p_memsz = PT_GNU_STACK_MEMSZ.get();
        mut_phdr_table.at_if(PHDR_PT_GNU_STACK_IDX)->p_align = {};
    }

    /// <!-- description -->
    ///   @brief Loads the initial state of an ELF file.
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_file the ELF file to load
    ///   @param phdr_table the program header table to use
    ///
    constexpr void
    load_elf_file(loader::ext_elf_file_t &mut_file, phdr_table_t const &phdr_table) noexcept
    {
        mut_file.e_type = bfelf::ET_EXEC.get();
        *mut_file.e_ident.at_if(bfelf::EI_MAG0) = bfelf::ELFMAG0.get();
        *mut_file.e_ident.at_if(bfelf::EI_MAG1) = bfelf::ELFMAG1.get();
        *mut_file.e_ident.at_if(bfelf::EI_MAG2) = bfelf::ELFMAG2.get();
        *mut_file.e_ident.at_if(bfelf::EI_MAG3) = bfelf::ELFMAG3.get();
        *mut_file.e_ident.at_if(bfelf::EI_CLASS) = bfelf::ELFCLASS64.get();
        *mut_file.e_ident.at_if(bfelf::EI_OSABI) = bfelf::ELFOSABI_SYSV.get();

        mut_file.e_phdr = phdr_table.data();
        mut_file.e_phnum = bsl::to_u16(phdr_table.size()).get();

        mut_file.e_entry = HYPERVISOR_PAGE_SIZE.get();
    }

    /// <!-- description -->
    ///   @brief Used to execute the actual checks. We put the checks in this
    ///     function so that we can validate the tests both at compile-time
    ///     and at run-time. If a bsl::ut_check fails, the tests will either
    ///     fail fast at run-time, or will produce a compile-time error.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Always returns bsl::exit_success.
    ///
    [[nodiscard]] constexpr auto
    tests() noexcept -> bsl::exit_code
    {
        bsl::ut_scenario{"initialize"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"initialize without tls"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table_without_tls(mut_phdr_table, elf_file_buf);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"initialize rpt initialize fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    mut_tls.test_ret = lib::UNIT_TEST_RPT_FAIL_INITIALIZE;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"initialize allocate PT_LOAD_RE_VADDR fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    mut_tls.test_virt = PT_LOAD_RE_VADDR;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"initialize allocate PT_LOAD_RO_VADDR fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    mut_tls.test_virt = PT_LOAD_RO_VADDR;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"initialize allocate PT_LOAD_RW_VADDR fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    mut_tls.test_virt = PT_LOAD_RW_VADDR;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"initialize allocate tls fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    mut_tls.test_virt = HYPERVISOR_EXT_TLS_ADDR;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                constexpr auto addr{(HYPERVISOR_EXT_TLS_ADDR + HYPERVISOR_PAGE_SIZE).checked()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    mut_tls.test_virt = addr;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"initialize tls file size is 0"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    mut_phdr_table.at_if(PHDR_PT_TLS_IDX)->p_filesz = {};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"initialize tls mem size is 0"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    mut_phdr_table.at_if(PHDR_PT_TLS_IDX)->p_memsz = {};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"initialize allocate stack fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    mut_tls.test_virt = HYPERVISOR_EXT_STACK_ADDR;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"initialize allocate fail stack fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    mut_tls.test_virt = HYPERVISOR_EXT_FAIL_STACK_ADDR;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"id"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(syscall::BF_INVALID_ID == mut_ext.id());
                    };

                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(syscall::BF_INVALID_ID != mut_ext.id());
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"bootstrap_ip"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                constexpr auto ip{0x1000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ext.bootstrap_ip().is_zero());
                    };

                    mut_ext.set_bootstrap_ip(ip);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(ip == mut_ext.bootstrap_ip());
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"vmexit_ip"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                constexpr auto ip{0x1000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ext.vmexit_ip().is_zero());
                    };

                    mut_ext.set_vmexit_ip(ip);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(ip == mut_ext.vmexit_ip());
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"fail_ip"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                constexpr auto ip{0x1000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ext.fail_ip().is_zero());
                    };

                    mut_ext.set_fail_ip(ip);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(ip == mut_ext.fail_ip());
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"handle"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));

                    auto const hndl{mut_ext.open_handle()};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(hndl == mut_ext.handle());
                        bsl::ut_check(mut_ext.is_handle_valid(hndl));
                        bsl::ut_check(mut_ext.open_handle().is_invalid());
                    };

                    mut_ext.close_handle();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(syscall::BF_INVALID_HANDLE == mut_ext.handle());
                        bsl::ut_check(!mut_ext.is_handle_valid(hndl));
                    };

                    mut_ext.close_handle();
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"alloc_page"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    bsl::ut_required_step(mut_ext.signal_vm_created(mut_tls, mut_page_pool, {}));
                    auto const page{mut_ext.alloc_page(mut_tls, mut_page_pool)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(page.virt.is_valid());
                        bsl::ut_check(page.phys.is_valid());
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"alloc_page fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    mut_tls.test_virt = bsl::safe_u64::failure();
                    auto const page{mut_ext.alloc_page(mut_tls, mut_page_pool)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(page.virt.is_invalid());
                        bsl::ut_check(page.phys.is_invalid());
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"alloc_huge"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                constexpr auto size{0x2000_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    bsl::ut_required_step(mut_ext.signal_vm_created(mut_tls, mut_page_pool, {}));
                    auto const page{
                        mut_ext.alloc_huge(mut_tls, mut_page_pool, mut_huge_pool, size)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(page.virt.is_valid());
                        bsl::ut_check(page.phys.is_valid());
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"alloc_huge unaligned size"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                constexpr auto size{0x2042_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    auto const page{
                        mut_ext.alloc_huge(mut_tls, mut_page_pool, mut_huge_pool, size)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(page.virt.is_valid());
                        bsl::ut_check(page.phys.is_valid());
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"alloc_huge size too large (or is it?)"} = [&]() noexcept {
            bsl::ut_given_at_runtime{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                constexpr auto size{0xFFFFFFFFFFFFFFFF_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    auto const page{
                        mut_ext.alloc_huge(mut_tls, mut_page_pool, mut_huge_pool, size)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(page.virt.is_invalid());
                        bsl::ut_check(page.phys.is_invalid());
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"alloc_huge alloc fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                constexpr auto size{0x2000_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    mut_huge_pool.set_allocate_fails();
                    auto const page{
                        mut_ext.alloc_huge(mut_tls, mut_page_pool, mut_huge_pool, size)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(page.virt.is_invalid());
                        bsl::ut_check(page.phys.is_invalid());
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"alloc_huge map fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                constexpr auto size{0x2000_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    mut_tls.test_virt = (HYPERVISOR_EXT_HUGE_POOL_ADDR + size).checked();
                    auto const page{
                        mut_ext.alloc_huge(mut_tls, mut_page_pool, mut_huge_pool, size)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(page.virt.is_invalid());
                        bsl::ut_check(page.phys.is_invalid());
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"alloc_huge too many allocations"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                constexpr auto size{0x2000_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    auto const page1{
                        mut_ext.alloc_huge(mut_tls, mut_page_pool, mut_huge_pool, size)};
                    auto const page2{
                        mut_ext.alloc_huge(mut_tls, mut_page_pool, mut_huge_pool, size)};
                    auto const page3{
                        mut_ext.alloc_huge(mut_tls, mut_page_pool, mut_huge_pool, size)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(page1.virt.is_valid());
                        bsl::ut_check(page1.phys.is_valid());
                        bsl::ut_check(page2.virt.is_valid());
                        bsl::ut_check(page2.phys.is_valid());
                        bsl::ut_check(page3.virt.is_invalid());
                        bsl::ut_check(page3.phys.is_invalid());
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"map_page_direct"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                constexpr auto phys{0x1000_umx};
                constexpr auto virt{(HYPERVISOR_EXT_DIRECT_MAP_ADDR + phys).checked()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    bsl::ut_required_step(mut_ext.signal_vm_created(mut_tls, mut_page_pool, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            virt == mut_ext.map_page_direct(mut_tls, mut_page_pool, {}, phys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"map_page_direct map fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                constexpr auto phys{0x1000_umx};
                constexpr auto virt{(HYPERVISOR_EXT_DIRECT_MAP_ADDR + phys).checked()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    bsl::ut_required_step(mut_ext.signal_vm_created(mut_tls, mut_page_pool, {}));
                    mut_tls.test_virt = virt.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mut_ext.map_page_direct(mut_tls, mut_page_pool, {}, phys).is_invalid());
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"unmap_page_direct"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                intrinsic_t const intrinsic{};
                constexpr auto phys{0x1000_umx};
                constexpr auto virt{(HYPERVISOR_EXT_DIRECT_MAP_ADDR + phys).checked()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    bsl::ut_required_step(mut_ext.signal_vm_created(mut_tls, mut_page_pool, {}));
                    bsl::ut_required_step(
                        mut_ext.map_page_direct(mut_tls, mut_page_pool, {}, phys));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mut_ext.unmap_page_direct(mut_tls, mut_page_pool, intrinsic, {}, virt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"unmap_page_direct unmap fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                intrinsic_t const intrinsic{};
                constexpr auto phys{0x1000_umx};
                constexpr auto virt{(HYPERVISOR_EXT_DIRECT_MAP_ADDR + phys).checked()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    bsl::ut_required_step(mut_ext.signal_vm_created(mut_tls, mut_page_pool, {}));
                    mut_tls.test_virt = virt.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_ext.unmap_page_direct(
                            mut_tls, mut_page_pool, intrinsic, {}, virt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"signal_vm_created"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ext.signal_vm_created(mut_tls, mut_page_pool, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"signal_vm_created direct map initialize fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    mut_tls.test_ret = lib::UNIT_TEST_RPT_FAIL_INITIALIZE;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_ext.signal_vm_created(mut_tls, mut_page_pool, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"signal_vm_destroyed"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    bsl::ut_required_step(mut_ext.signal_vm_created(mut_tls, mut_page_pool, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_ext.signal_vm_destroyed(mut_tls, mut_page_pool, {});
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"signal_vm_active"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    bsl::ut_required_step(mut_ext.signal_vm_created(mut_tls, mut_page_pool, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_ext.signal_vm_active(mut_tls, mut_intrinsic, {});
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"start"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    bsl::ut_required_step(mut_ext.signal_vm_created(mut_tls, mut_page_pool, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_ext.is_started());
                        bsl::ut_check(mut_ext.start(mut_tls, mut_intrinsic));
                        bsl::ut_check(mut_ext.is_started());
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"start call_ext fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    mut_file.e_entry = bsl::safe_u64::magic_1().get();
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    bsl::ut_required_step(mut_ext.signal_vm_created(mut_tls, mut_page_pool, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_ext.start(mut_tls, mut_intrinsic));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"start more than once"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    bsl::ut_required_step(mut_ext.signal_vm_created(mut_tls, mut_page_pool, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ext.start(mut_tls, mut_intrinsic));
                        bsl::ut_check(mut_ext.start(mut_tls, mut_intrinsic));
                        bsl::ut_check(mut_ext.start(mut_tls, mut_intrinsic));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"bootstrap"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    bsl::ut_required_step(mut_ext.signal_vm_created(mut_tls, mut_page_pool, {}));
                    mut_ext.set_bootstrap_ip(HYPERVISOR_PAGE_SIZE);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ext.bootstrap(mut_tls, mut_intrinsic));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"bootstrap call_ext fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    bsl::ut_required_step(mut_ext.signal_vm_created(mut_tls, mut_page_pool, {}));
                    mut_ext.set_bootstrap_ip(bsl::safe_u64::magic_1());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_ext.bootstrap(mut_tls, mut_intrinsic));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"bootstrap more than once"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    bsl::ut_required_step(mut_ext.signal_vm_created(mut_tls, mut_page_pool, {}));
                    mut_ext.set_bootstrap_ip(HYPERVISOR_PAGE_SIZE);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ext.bootstrap(mut_tls, mut_intrinsic));
                        bsl::ut_check(mut_ext.bootstrap(mut_tls, mut_intrinsic));
                        bsl::ut_check(mut_ext.bootstrap(mut_tls, mut_intrinsic));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"bootstrap no ip"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    bsl::ut_required_step(mut_ext.signal_vm_created(mut_tls, mut_page_pool, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_ext.bootstrap(mut_tls, mut_intrinsic));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"vmexit"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    bsl::ut_required_step(mut_ext.signal_vm_created(mut_tls, mut_page_pool, {}));
                    mut_ext.set_vmexit_ip(HYPERVISOR_PAGE_SIZE);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ext.vmexit(mut_tls, mut_intrinsic, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"vmexit call_ext fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    bsl::ut_required_step(mut_ext.signal_vm_created(mut_tls, mut_page_pool, {}));
                    mut_ext.set_vmexit_ip(bsl::safe_u64::magic_1());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_ext.vmexit(mut_tls, mut_intrinsic, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"vmexit more than once"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    bsl::ut_required_step(mut_ext.signal_vm_created(mut_tls, mut_page_pool, {}));
                    mut_ext.set_vmexit_ip(HYPERVISOR_PAGE_SIZE);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ext.vmexit(mut_tls, mut_intrinsic, {}));
                        bsl::ut_check(mut_ext.vmexit(mut_tls, mut_intrinsic, {}));
                        bsl::ut_check(mut_ext.vmexit(mut_tls, mut_intrinsic, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"fail"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    bsl::ut_required_step(mut_ext.signal_vm_created(mut_tls, mut_page_pool, {}));
                    mut_ext.set_fail_ip(HYPERVISOR_PAGE_SIZE);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_ext.is_executing_fail());
                        bsl::ut_check(mut_ext.fail(mut_tls, mut_intrinsic, {}, {}));
                        bsl::ut_check(!mut_ext.is_executing_fail());
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"fail call_ext fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    bsl::ut_required_step(mut_ext.signal_vm_created(mut_tls, mut_page_pool, {}));
                    mut_ext.set_fail_ip(bsl::safe_u64::magic_1());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_ext.fail(mut_tls, mut_intrinsic, {}, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"fail more than once"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    bsl::ut_required_step(mut_ext.signal_vm_created(mut_tls, mut_page_pool, {}));
                    mut_ext.set_fail_ip(HYPERVISOR_PAGE_SIZE);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ext.fail(mut_tls, mut_intrinsic, {}, {}));
                        bsl::ut_check(mut_ext.fail(mut_tls, mut_intrinsic, {}, {}));
                        bsl::ut_check(mut_ext.fail(mut_tls, mut_intrinsic, {}, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"dump"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_t mut_ext{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_ext.dump({});
                };
            };
        };

        bsl::ut_scenario{"dump after start"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto const elf_file_buf{get_elf_file_buf()};
                loader::ext_elf_file_t mut_file{};
                phdr_table_t mut_phdr_table{};
                ext_t mut_ext{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                root_page_table_t mut_rpt{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = NUM_ONLINE_PPS.get();
                    load_elf_file(mut_file, mut_phdr_table);
                    load_phdr_table(mut_phdr_table, elf_file_buf);
                    bsl::ut_required_step(
                        mut_ext.initialize(mut_tls, mut_page_pool, {}, &mut_file, mut_rpt));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_ext.dump({});
                    };
                    bsl::ut_required_step(mut_ext.open_handle());
                    bsl::ut_required_step(mut_ext.signal_vm_created(mut_tls, mut_page_pool, {}));
                    bsl::ut_required_step(mut_ext.start(mut_tls, mut_intrinsic));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_ext.dump({});
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_ext.release(mut_tls, mut_page_pool, mut_huge_pool);
                        clr_elf_file_buf(elf_file_buf);
                    };
                };
            };
        };

        bsl::ut_scenario{"dump with ips set"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_t mut_ext{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_ext.set_bootstrap_ip(HYPERVISOR_PAGE_SIZE);
                    mut_ext.set_vmexit_ip(HYPERVISOR_PAGE_SIZE);
                    mut_ext.set_fail_ip(HYPERVISOR_PAGE_SIZE);
                    bsl::ut_then{} = [&]() noexcept {
                        mut_ext.dump({});
                    };
                };
            };
        };

        return bsl::ut_success();
    }
}

/// <!-- description -->
///   @brief Main function for this unit test. If a call to bsl::ut_check() fails
///     the application will fast fail. If all calls to bsl::ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
[[nodiscard]] auto
main() noexcept -> bsl::exit_code
{
    bsl::enable_color();

    static_assert(mk::tests() == bsl::ut_success());
    return mk::tests();
}
