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

#include <bfelf/bfelf_elf64_ehdr_t.h>
#include <bfelf/bfelf_elf64_phdr_t.h>
#include <bfelf/bfelf_elf64_shdr_t.h>
#include <mk_args_t.h>       // IWYU pragma: keep
#include <state_save_t.h>    // IWYU pragma: keep
#include <types.h>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace helpers
{
    extern "C"
    {
        /// @brief unit test control for platform_alloc
        extern bsl::int32 g_mut_platform_alloc;
        /// @brief unit test control for platform_alloc_contiguous
        extern bsl::int32 g_mut_platform_alloc_contiguous;
        /// @brief unit test control for platform_virt_to_phys
        extern bsl::int32 g_mut_platform_virt_to_phys;
        /// @brief unit test control for platform_copy_from_user
        extern bsl::int32 g_mut_platform_copy_from_user;
        /// @brief unit test control for platform_copy_to_user
        extern bsl::int32 g_mut_platform_copy_to_user;
        /// @brief unit test control for platform_arch_init
        extern bsl::int32 g_mut_platform_arch_init;

        /// @brief unit test control for alloc_and_copy_mk_code_aliases
        extern bsl::int32 g_mut_alloc_and_copy_mk_code_aliases;
        /// @brief unit test control for check_cpu_configuration
        extern bsl::int32 g_mut_check_cpu_configuration;
        /// @brief unit test control for map_4k_page
        extern bsl::int32 g_mut_map_4k_page;
        /// @brief unit test control for send_command_stop
        extern bsl::int32 g_mut_send_command_stop;

        /// @brief return value for demote
        constinit inline bsl::safe_i32 g_mut_demote{};
        /// @brief return value for enable_hve
        constinit inline bsl::safe_i32 g_mut_enable_hve{};
        /// @brief return value for intrinsic_cpuid
        constinit inline bsl::safe_i32 g_mut_intrinsic_cpuid{};
        /// @brief return value for intrinsic_inb
        constinit inline bsl::safe_i32 g_mut_intrinsic_inb{};
        /// @brief return value for intrinsic_rdmsr
        constinit inline bsl::safe_i32 g_mut_intrinsic_rdmsr{};
        /// @brief return value for intrinsic_scr0
        constinit inline bsl::safe_i32 g_mut_intrinsic_scr0{};
        /// @brief return value for intrinsic_scr4
        constinit inline bsl::safe_i32 g_mut_intrinsic_scr4{};
        /// @brief return value for intrinsic_scs
        constinit inline bsl::safe_i32 g_mut_intrinsic_scs{};
        /// @brief return value for intrinsic_sds
        constinit inline bsl::safe_i32 g_mut_intrinsic_sds{};
        /// @brief return value for intrinsic_ses
        constinit inline bsl::safe_i32 g_mut_intrinsic_ses{};
        /// @brief return value for intrinsic_sfs
        constinit inline bsl::safe_i32 g_mut_intrinsic_sfs{};
        /// @brief return value for intrinsic_sgs
        constinit inline bsl::safe_i32 g_mut_intrinsic_sgs{};
        /// @brief return value for intrinsic_sldtr
        constinit inline bsl::safe_i32 g_mut_intrinsic_sldtr{};
        /// @brief return value for intrinsic_sss
        constinit inline bsl::safe_i32 g_mut_intrinsic_sss{};
        /// @brief return value for intrinsic_str
        constinit inline bsl::safe_i32 g_mut_intrinsic_str{};
    }

    /// <!-- description -->
    ///   @brief Resets common tests
    ///
    constexpr void
    reset() noexcept
    {
        g_mut_platform_alloc = 0;
        g_mut_platform_alloc_contiguous = 0;
        g_mut_platform_virt_to_phys = 0;
        g_mut_platform_copy_from_user = 0;
        g_mut_platform_copy_to_user = 0;
        g_mut_platform_arch_init = 0;

        g_mut_alloc_and_copy_mk_code_aliases = 0;
        g_mut_check_cpu_configuration = 0;
        g_mut_map_4k_page = 0;
        g_mut_send_command_stop = 0;

        g_mut_demote = 0;
    }

    /// <!-- description -->
    ///   @brief Resets tests for x64
    ///
    constexpr void
    reset_x64() noexcept
    {
        g_mut_platform_alloc = 0;
        g_mut_platform_alloc_contiguous = 0;
        g_mut_platform_virt_to_phys = 0;
        g_mut_platform_copy_from_user = 0;
        g_mut_platform_copy_to_user = 0;
        g_mut_platform_arch_init = 0;

        g_mut_demote = 0;
        g_mut_enable_hve = 0;
        g_mut_intrinsic_cpuid = 0;
        g_mut_intrinsic_inb = 0;
        g_mut_intrinsic_rdmsr = 0;
        g_mut_intrinsic_scr0 = 0;
        g_mut_intrinsic_scr4 = 0;
        g_mut_intrinsic_scs = 0;
        g_mut_intrinsic_sds = 0;
        g_mut_intrinsic_ses = 0;
        g_mut_intrinsic_sfs = 0;
        g_mut_intrinsic_sgs = 0;
        g_mut_intrinsic_sldtr = 0;
        g_mut_intrinsic_sss = 0;
        g_mut_intrinsic_str = 0;
    }

    /// <!-- description -->
    ///   @brief Initializes common tests
    ///
    constexpr void
    init() noexcept
    {
        reset();
    }

    /// <!-- description -->
    ///   @brief Initializes tets for x64
    ///
    constexpr void
    init_x64() noexcept
    {
        reset_x64();
    }

    /// <!-- description -->
    ///   @brief Cleanup and returns success
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns success
    ///
    [[nodiscard]] constexpr auto
    fini() noexcept -> int32_t
    {
        return bsl::ut_success();
    }

    /// <!-- description -->
    ///   @brief The same as bsl::ut_check, but checks for LOADER_SUCCESS
    ///
    /// <!-- inputs/outputs -->
    ///   @param test if LOADER_SUCCESS, the test passes. Otherwise the test
    ///     will fast fail with an error.
    ///   @param sloc the location of the test
    ///   @return bsl::ut_check(LOADER_SUCCESS == test, sloc)
    ///
    [[maybe_unused]] constexpr auto
    ut_check(bsl::int64 const test, bsl::source_location const &sloc = bsl::here()) noexcept -> bool
    {
        return bsl::ut_check(LOADER_SUCCESS == test, sloc);
    }

    /// <!-- description -->
    ///   @brief The same as bsl::ut_check, but checks for LOADER_FAILURE
    ///
    /// <!-- inputs/outputs -->
    ///   @param test if LOADER_FAILURE, the test passes. Otherwise the test
    ///     will fast fail with an error.
    ///   @param sloc the location of the test
    ///   @return bsl::ut_check(LOADER_FAILURE == test, sloc)
    ///
    [[maybe_unused]] constexpr auto
    ut_fails(bsl::int64 const test, bsl::source_location const &sloc = bsl::here()) noexcept -> bool
    {
        return bsl::ut_check(LOADER_FAILURE == test, sloc);
    }

    /// <!-- description -->
    ///   @brief Returns a bsl::uint8 * version of pudm_udm_val
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of pointer to convert
    ///   @param pudm_udm_val the pointer to convert
    ///   @return Returns a bsl::uint8 * version of pudm_udm_val
    ///
    template<typename T>
    [[nodiscard]] auto
    to_u8_ptr(T &&pudm_udm_val) noexcept -> bsl::uint8 *
    {
        return reinterpret_cast<bsl::uint8 *>(pudm_udm_val);
    }

    /// @brief max number of segments in a file_t
    constexpr auto NUM_SEGMENTS{42_umx};
    /// @brief max number of sections in a file_t
    constexpr auto NUM_SECTIONS{42_umx};

    /// <!-- description -->
    ///   @brief Represents an ELF file
    ///
    struct file_t final    // NOLINT
    {
        /// @brief the ELF file header
        bfelf_elf64_ehdr_t ehdr{};
        /// @brief the ELF file segment table
        bsl::array<bfelf_elf64_phdr_t, NUM_SEGMENTS.get()> phdrtbl{};
        /// @brief the ELF file section table
        bsl::array<bfelf_elf64_shdr_t, NUM_SECTIONS.get()> shdrtbl{};
        /// @brief a dummy segment
        bsl::array<bsl::uint8, HYPERVISOR_PAGE_SIZE> segment{};
        /// @brief a dummy section
        bsl::array<bsl::uint8, HYPERVISOR_PAGE_SIZE> section{};
    };

    /// <!-- description -->
    ///   @brief Returns the offset of the phdrtbl in a file_t
    ///
    /// <!-- inputs/outputs -->
    ///   @param file the file_t to get the offset from
    ///   @return Returns the offset of the phdrtbl in a file_t
    ///
    [[nodiscard]] constexpr auto
    phdrtbl_offset(file_t const &file) noexcept -> bfelf_elf64_phdr_t *
    {
        bsl::safe_u64 addr1{reinterpret_cast<bsl::uint64>(&file)};            // NOLINT
        bsl::safe_u64 addr2{reinterpret_cast<bsl::uint64>(&file.phdrtbl)};    // NOLINT

        return reinterpret_cast<bfelf_elf64_phdr_t *>((addr2 - addr1).checked().get());
    }

    /// <!-- description -->
    ///   @brief Returns the offset of the shdrtbl in a file_t
    ///
    /// <!-- inputs/outputs -->
    ///   @param file the file_t to get the offset from
    ///   @return Returns the offset of the shdrtbl in a file_t
    ///
    [[nodiscard]] constexpr auto
    shdrtbl_offset(file_t const &file) noexcept -> bfelf_elf64_shdr_t *
    {
        bsl::safe_u64 addr1{reinterpret_cast<bsl::uint64>(&file)};            // NOLINT
        bsl::safe_u64 addr2{reinterpret_cast<bsl::uint64>(&file.shdrtbl)};    // NOLINT

        return reinterpret_cast<bfelf_elf64_shdr_t *>((addr2 - addr1).checked().get());
    }

    /// <!-- description -->
    ///   @brief Returns the offset of the segments in a file_t
    ///
    /// <!-- inputs/outputs -->
    ///   @param file the file_t to get the offset from
    ///   @return Returns the offset of the segments in a file_t
    ///
    [[nodiscard]] constexpr auto
    segment_offset(file_t const &file) noexcept -> bsl::uint8 *
    {
        bsl::safe_u64 addr1{reinterpret_cast<bsl::uint64>(&file)};            // NOLINT
        bsl::safe_u64 addr2{reinterpret_cast<bsl::uint64>(&file.segment)};    // NOLINT

        return reinterpret_cast<bsl::uint8 *>((addr2 - addr1).checked().get());
    }

    /// <!-- description -->
    ///   @brief Returns the offset of the sections in a file_t
    ///
    /// <!-- inputs/outputs -->
    ///   @param file the file_t to get the offset from
    ///   @return Returns the offset of the sections in a file_t
    ///
    [[nodiscard]] constexpr auto
    section_offset(file_t const &file) noexcept -> bsl::uint8 *
    {
        bsl::safe_u64 addr1{reinterpret_cast<bsl::uint64>(&file)};            // NOLINT
        bsl::safe_u64 addr2{reinterpret_cast<bsl::uint64>(&file.section)};    // NOLINT

        return reinterpret_cast<bsl::uint8 *>((addr2 - addr1).checked().get());
    }

    /// <!-- description -->
    ///   @brief Initializes a file_t
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_file the file to initialize
    ///
    constexpr void
    init_file(file_t &mut_file) noexcept
    {
        mut_file.ehdr.e_ident[bfelf_ei_mag0] = bfelf_elfmag0;
        mut_file.ehdr.e_ident[bfelf_ei_mag1] = bfelf_elfmag1;
        mut_file.ehdr.e_ident[bfelf_ei_mag2] = bfelf_elfmag2;
        mut_file.ehdr.e_ident[bfelf_ei_mag3] = bfelf_elfmag3;
        mut_file.ehdr.e_ident[bfelf_ei_class] = bfelf_elfclass64;
        mut_file.ehdr.e_ident[bfelf_ei_osabi] = bfelf_elfosabi_sysv;
        mut_file.ehdr.e_type = bfelf_et_exec;
        mut_file.ehdr.e_phdr = phdrtbl_offset(mut_file);
        mut_file.ehdr.e_phnum = bsl::to_u16(mut_file.phdrtbl.size()).get();
        mut_file.ehdr.e_shdr = shdrtbl_offset(mut_file);
        mut_file.ehdr.e_shnum = bsl::to_u16(mut_file.shdrtbl.size()).get();

        for (auto &mut_phdr : mut_file.phdrtbl) {
            mut_phdr.p_offset = segment_offset(mut_file);
            mut_phdr.p_filesz = mut_file.segment.size().get();
            mut_phdr.p_memsz = mut_file.segment.size().get();
        }

        for (auto &mut_shdr : mut_file.shdrtbl) {
            mut_shdr.sh_offset = section_offset(mut_file);
            mut_shdr.sh_size = bsl::to_u32(mut_file.section.size()).get();
        }

        mut_file.phdrtbl.front().p_type = bfelf_pt_load;
    }

    /// <!-- description -->
    ///   @brief Disables Hardware Virtualization Extensions
    ///
    extern "C" void
    // NOLINTNEXTLINE(misc-definitions-in-headers)
    disable_hve(void) noexcept
    {}

    /// <!-- description -->
    ///   @brief Enables Hardware Virtualization Extensions
    ///
    /// <!-- inputs/outputs -->
    ///   @param pmut_state the mk state save containing the HVE page
    ///   @return Returns 0 on success
    ///
    extern "C" [[nodiscard]] auto
    // NOLINTNEXTLINE(misc-definitions-in-headers)
    enable_hve(struct state_save_t *const pmut_state) noexcept -> bsl::int64
    {
        bsl::discard(pmut_state);

        if (g_mut_enable_hve > 0) {
            g_mut_enable_hve = (g_mut_enable_hve - 1).checked();
            return LOADER_FAILURE;
        }

        return LOADER_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Executes the CPUID instruction given the provided EAX and ECX
    ///     and returns the results
    ///
    /// <!-- inputs/outputs -->
    ///   @param pmut_eax the index used by CPUID, returns resulting eax
    ///   @param pmut_ebx returns resulting ebx
    ///   @param pmut_ecx the subindex used by CPUID, returns the resulting ecx
    ///   @param pmut_edx returns resulting edx to.
    ///
    extern "C" void
    // NOLINTNEXTLINE(misc-definitions-in-headers)
    intrinsic_cpuid(
        uint32_t *const pmut_eax,
        uint32_t *const pmut_ebx,
        uint32_t *const pmut_ecx,
        uint32_t *const pmut_edx) noexcept
    {
        if (g_mut_intrinsic_cpuid > 0) {
            g_mut_intrinsic_cpuid = (g_mut_intrinsic_cpuid - 1).checked();
            *pmut_eax = 0xFFFFFFFFU;
            *pmut_ebx = 0xFFFFFFFFU;
            *pmut_ecx = 0xFFFFFFFFU;
            *pmut_edx = 0xFFFFFFFFU;
            return;
        }

        if (g_mut_intrinsic_cpuid < 0) {
            g_mut_intrinsic_cpuid = (g_mut_intrinsic_cpuid + 1).checked();
            *pmut_eax = 0U;
            *pmut_ebx = 0U;
            *pmut_ecx = 0U;
            *pmut_edx = 0U;
            return;
        }

        *pmut_eax = 0U;
        *pmut_edx = 0xFFFFFFFFU;
    }

    /// <!-- description -->
    ///   @brief Executes the OUTB instruction given the provided Port
    ///     and value
    ///
    /// <!-- inputs/outputs -->
    ///   @param port the port to write to
    ///   @param val the value to write to the given Port
    ///
    extern "C" void
    // NOLINTNEXTLINE(misc-definitions-in-headers)
    intrinsic_outb(uint16_t const port, uint8_t const val) noexcept
    {
        bsl::discard(port);
        bsl::discard(val);
    }

    /// <!-- description -->
    ///   @brief Executes the RDMSR instruction given the provided MSR
    ///     and returns the results
    ///
    /// <!-- inputs/outputs -->
    ///   @param ecx the MSR to read
    ///   @return Returns the resulting MSR value
    ///
    extern "C" [[nodiscard]] auto
    // NOLINTNEXTLINE(misc-definitions-in-headers)
    intrinsic_rdmsr(uint32_t const ecx) noexcept -> bsl::uint64
    {
        bsl::discard(ecx);
        return bsl::to_u64(g_mut_intrinsic_rdmsr).get();
    }

    /// <!-- description -->
    ///   @brief Reads the CR0 control register and returns the result.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Reads the CR0 control register and returns the result.
    ///
    extern "C" [[nodiscard]] auto
    // NOLINTNEXTLINE(misc-definitions-in-headers)
    intrinsic_scr0(void) noexcept -> bsl::uint64
    {
        return bsl::to_u64(g_mut_intrinsic_scr0).get();
    }

    /// <!-- description -->
    ///   @brief Reads the CR4 control register and returns the result.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Reads the CR4 control register and returns the result.
    ///
    extern "C" [[nodiscard]] auto
    // NOLINTNEXTLINE(misc-definitions-in-headers)
    intrinsic_scr4(void) noexcept -> bsl::uint64
    {
        return bsl::to_u64(g_mut_intrinsic_scr4).get();
    }

    /// <!-- description -->
    ///   @brief Reads the CS segment register and returns the result.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Reads the CS segment register and returns the result.
    ///
    extern "C" [[nodiscard]] auto
    // NOLINTNEXTLINE(misc-definitions-in-headers)
    intrinsic_scs(void) noexcept -> bsl::uint16
    {
        return bsl::to_u16(g_mut_intrinsic_scs).get();
    }

    /// <!-- description -->
    ///   @brief Reads the DS segment register and returns the result.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Reads the DS segment register and returns the result.
    ///
    extern "C" [[nodiscard]] auto
    // NOLINTNEXTLINE(misc-definitions-in-headers)
    intrinsic_sds(void) noexcept -> bsl::uint16
    {
        return bsl::to_u16(g_mut_intrinsic_sds).get();
    }

    /// <!-- description -->
    ///   @brief Reads the ES segment register and returns the result.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Reads the ES segment register and returns the result.
    ///
    extern "C" [[nodiscard]] auto
    // NOLINTNEXTLINE(misc-definitions-in-headers)
    intrinsic_ses(void) noexcept -> bsl::uint16
    {
        return bsl::to_u16(g_mut_intrinsic_ses).get();
    }

    /// <!-- description -->
    ///   @brief Reads the FS segment register and returns the result.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Reads the FS segment register and returns the result.
    ///
    extern "C" [[nodiscard]] auto
    // NOLINTNEXTLINE(misc-definitions-in-headers)
    intrinsic_sfs(void) noexcept -> bsl::uint16
    {
        return bsl::to_u16(g_mut_intrinsic_sfs).get();
    }

    /// <!-- description -->
    ///   @brief Executes the SGDT instruction given a pointer to a
    ///     global_descriptor_table_register_t.
    ///
    /// <!-- inputs/outputs -->
    ///   @param pmut_gdtr a pointer to a global_descriptor_table_register_t
    ///
    extern "C" void
    // NOLINTNEXTLINE(misc-definitions-in-headers)
    intrinsic_sgdt(struct global_descriptor_table_register_t *const pmut_gdtr) noexcept
    {
        bsl::discard(pmut_gdtr);
    }

    /// <!-- description -->
    ///   @brief Reads the GS segment register and returns the result.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Reads the GS segment register and returns the result.
    ///
    extern "C" [[nodiscard]] auto
    // NOLINTNEXTLINE(misc-definitions-in-headers)
    intrinsic_sgs(void) noexcept -> bsl::uint16
    {
        return bsl::to_u16(g_mut_intrinsic_sgs).get();
    }

    /// <!-- description -->
    ///   @brief Executes the SIDT instruction given a pointer to a
    ///     interrupt_descriptor_table_register_t.
    ///
    /// <!-- inputs/outputs -->
    ///   @param pmut_idtr a pointer to a interrupt_descriptor_table_register_t
    ///
    extern "C" void
    // NOLINTNEXTLINE(misc-definitions-in-headers)
    intrinsic_sidt(struct interrupt_descriptor_table_register_t *const pmut_idtr) noexcept
    {
        bsl::discard(pmut_idtr);
    }

    /// <!-- description -->
    ///   @brief Reads the LDTR segment register and returns the result.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Reads the LDTR segment register and returns the result.
    ///
    extern "C" [[nodiscard]] auto
    // NOLINTNEXTLINE(misc-definitions-in-headers)
    intrinsic_sldtr(void) noexcept -> bsl::uint16
    {
        return bsl::to_u16(g_mut_intrinsic_sldtr).get();
    }

    /// <!-- description -->
    ///   @brief Reads the SS segment register and returns the result.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Reads the SS segment register and returns the result.
    ///
    extern "C" [[nodiscard]] auto
    // NOLINTNEXTLINE(misc-definitions-in-headers)
    intrinsic_sss(void) noexcept -> bsl::uint16
    {
        return bsl::to_u16(g_mut_intrinsic_sss).get();
    }

    /// <!-- description -->
    ///   @brief Reads the TR segment register and returns the result.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Reads the TR segment register and returns the result.
    ///
    extern "C" [[nodiscard]] auto
    // NOLINTNEXTLINE(misc-definitions-in-headers)
    intrinsic_str(void) noexcept -> bsl::uint16
    {
        return bsl::to_u16(g_mut_intrinsic_str).get();
    }

#ifndef DO_NOT_INCLUDE_ALIASES

    /// <!-- description -->
    ///   @brief This function executes the microkernel, demoting the current
    ///     OS into a virtual machine.
    ///
    /// <!-- inputs/outputs -->
    ///   @param args the arguments to pass to the microkernel
    ///   @param mk_state the microkernel's state save
    ///   @param root_vp_state the root vp's state save
    ///   @return LOADER_SUCCESS on success, LOADER_FAILURE on failure.
    ///
    extern "C" [[nodiscard]] auto
    // NOLINTNEXTLINE(misc-definitions-in-headers)
    demote(
        mk_args_t const *const args,
        state_save_t const *const mk_state,
        state_save_t const *const root_vp_state) noexcept -> int64_t
    {
        bsl::discard(args);
        bsl::discard(mk_state);
        bsl::discard(root_vp_state);

        if (g_mut_demote > 0) {
            g_mut_demote = (g_mut_demote - 1).checked();
            return LOADER_FAILURE;
        }

        return LOADER_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief This promotes the OS by overwriting the state of the microkernel
    ///     with the OS's state. This can be called when an error occurs during
    ///     the initialization of the microkernel and it can also be called when
    ///     the hypervisor is asked to stop.
    ///
    /// <!-- inputs/outputs -->
    ///   @param args the arguments that were passed to the microkernel
    ///   @return LOADER_SUCCESS on success, LOADER_FAILURE on failure.
    ///
    extern "C" [[nodiscard]] auto
    // NOLINTNEXTLINE(misc-definitions-in-headers)
    promote(mk_args_t const *const args) noexcept -> int64_t
    {
        bsl::discard(args);
        return LOADER_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Writes a character "c" to the serial device.
    ///
    /// <!-- inputs/outputs -->
    ///   @param c the character to write
    ///
    extern "C" void
    // NOLINTNEXTLINE(misc-definitions-in-headers)
    serial_write_c(char const c) noexcept
    {
        bsl::discard(c);
    }

    /// <!-- description -->
    ///   @brief Writes a hexidecimal number "val" to the serial device.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val the hexidecimal number to write
    ///
    extern "C" void
    // NOLINTNEXTLINE(misc-definitions-in-headers)
    serial_write_hex(uint64_t const val) noexcept
    {
        bsl::discard(val);
    }

    /// <!-- description -->
    ///   @brief Defines the default exception service routine for ESRs
    ///
    extern "C" void
    // NOLINTNEXTLINE(misc-definitions-in-headers)
    esr_default(void) noexcept
    {}

    /// <!-- description -->
    ///   @brief Defines the exception service routine for double fault
    ///
    extern "C" void
    // NOLINTNEXTLINE(misc-definitions-in-headers)
    esr_df(void) noexcept
    {}

    /// <!-- description -->
    ///   @brief Defines the exception service routine for general protection fault
    ///
    extern "C" void
    // NOLINTNEXTLINE(misc-definitions-in-headers)
    esr_gpf(void) noexcept
    {}

    /// <!-- description -->
    ///   @brief Defines the exception service routine for NMIs
    ///
    extern "C" void
    // NOLINTNEXTLINE(misc-definitions-in-headers)
    esr_nmi(void) noexcept
    {}

    /// <!-- description -->
    ///   @brief Defines the exception service routine for page faults
    ///
    extern "C" void
    // NOLINTNEXTLINE(misc-definitions-in-headers)
    esr_pf(void) noexcept
    {}

#endif
}
