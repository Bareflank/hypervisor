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

#ifndef BFELF_ELF64_EHDR_T_HPP
#define BFELF_ELF64_EHDR_T_HPP

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/source_location.hpp>
#include <bsl/span.hpp>

#pragma pack(push, 1)

namespace bfelf
{
    /// @brief e_ident[EI_MAG0] contains 0x7FU for file identification
    constexpr auto EI_MAG0{0_umax};
    /// @brief e_ident[EI_MAG1] contains 0x45U for file identification
    constexpr auto EI_MAG1{1_umax};
    /// @brief e_ident[EI_MAG2] contains 0x4CU for file identification
    constexpr auto EI_MAG2{2_umax};
    /// @brief e_ident[EI_MAG3] contains 0x46U for file identification
    constexpr auto EI_MAG3{3_umax};
    /// @brief e_ident[EI_CLASS] identifies if the file is 32bit or 64 bit
    constexpr auto EI_CLASS{4_umax};
    /// @brief e_ident[EI_DATA] specifies the data bit encoding of the file
    constexpr auto EI_DATA{5_umax};
    /// @brief e_ident[EI_VERSION] identifies the version of the file
    constexpr auto EI_VERSION{6_umax};
    /// @brief e_ident[EI_OSABI] identifies file's ABI scheme
    constexpr auto EI_OSABI{7_umax};
    /// @brief e_ident[EI_ABIVERSION] identifies file's ABI version
    constexpr auto EI_ABIVERSION{8_umax};
    /// @brief defines the size of e_ident
    constexpr auto EI_NIDENT{16_umax};

    /// @brief defines the expected e_ident[EI_MAG0] value
    constexpr auto ELFMAG0{0x7F_u8};
    /// @brief defines the expected e_ident[EI_MAG1] value
    constexpr auto ELFMAG1{0x45_u8};
    /// @brief defines the expected e_ident[EI_MAG2] value
    constexpr auto ELFMAG2{0x4C_u8};
    /// @brief defines the expected e_ident[EI_MAG3] value
    constexpr auto ELFMAG3{0x46_u8};

    /// @brief defines e_ident[EI_CLASS] for 32bit objects
    constexpr auto ELFCLASS32{1_u8};
    /// @brief defines e_ident[EI_CLASS] for 64bit objects
    constexpr auto ELFCLASS64{2_u8};

    /// @brief defines e_ident[EI_DATA] for little endian
    constexpr auto ELFDATA2LSB{1_u8};
    /// @brief defines e_ident[EI_DATA] for big endian
    constexpr auto ELFDATA2MSB{2_u8};

    /// @brief defines e_ident[EI_OSABI] for system v abi
    constexpr auto ELFOSABI_SYSV{0_u8};
    /// @brief defines e_ident[EI_OSABI] for hp-ux operating system
    constexpr auto ELFOSABI_HPUX{1_u8};
    /// @brief defines e_ident[EI_OSABI] for standalone applications
    constexpr auto ELFOSABI_STANDALONE{255_u8};

    /// @brief defines e_type for no file type
    constexpr auto ET_NONE{0_u16};
    /// @brief defines e_type for an relocatable object file
    constexpr auto ET_REL{1_u16};
    /// @brief defines e_type for an executable file
    constexpr auto ET_EXEC{2_u16};
    /// @brief defines e_type for an shared object file
    constexpr auto ET_DYN{3_u16};
    /// @brief defines e_type for an core file
    constexpr auto ET_CORE{4_u16};
    /// @brief defines e_type for an environment-specific use (lo)
    constexpr auto ET_LOOS{0xFE00_u16};
    /// @brief defines e_type for an environment-specific use (hi)
    constexpr auto ET_HIOS{0xFEFF_u16};
    /// @brief defines e_type for an processor-specific use (lo)
    constexpr auto ET_LOPROC{0xFF00_u16};
    /// @brief defines e_type for an processor-specific use (hi)
    constexpr auto ET_HIPROC{0xFFFF_u16};

    /// @struct elf64_ehdr_t
    ///
    /// <!-- description -->
    ///   @brief The file header is located at the beginning of the file,
    ///     and is used to locate the other parts of the file
    ///
    struct elf64_ehdr_t final
    {
        /// @brief ELF identification
        bsl::array<bsl::uint8, EI_NIDENT.get()> e_ident;
        /// @brief object file type
        bsl::uint16 e_type;
        /// @brief machine type
        bsl::uint16 e_machine;
        /// @brief object file version
        bsl::uint32 e_version;
        /// @brief entry point address
        bsl::uint64 e_entry;
        /// @brief program header offset
        bsl::uint64 e_phoff;
        /// @brief section header offset
        bsl::uint64 e_shoff;
        /// @brief processor-specific flags
        bsl::uint32 e_flags;
        /// @brief ELF header size
        bsl::uint16 e_ehsize;
        /// @brief size of program header entry
        bsl::uint16 e_phentsize;
        /// @brief number of program header entries
        bsl::uint16 e_phnum;
        /// @brief size of section header entry
        bsl::uint16 e_shentsize;
        /// @brief number of section header entries
        bsl::uint16 e_shnum;
        /// @brief section name string table index
        bsl::uint16 e_shstrndx;
    };

    /// <!-- description -->
    ///   @brief Returns a pointer to an ELF header given an ELF file
    ///
    /// <!-- inputs/outputs -->
    ///   @param file the ELF file to get the header from
    ///   @return returns a pointer to the ELF header, or nullptr on error
    ///
    [[nodiscard]] constexpr auto
    get_elf64_ehdr(bsl::span<bsl::uint8 const> const &file) noexcept -> elf64_ehdr_t const *
    {
        if (file.empty()) {
            bsl::error() << "invalid ELF file\n" << bsl::here();
            return nullptr;
        }

        if (file.size() < sizeof(elf64_ehdr_t)) {
            bsl::error() << "invalid ELF file\n" << bsl::here();
            return nullptr;
        }

        return static_cast<elf64_ehdr_t const *>(static_cast<void const *>(file.data()));
    }

    /// <!-- description -->
    ///   @brief Checks whether or not a given ELF file is in a format that
    ///     this ELF loader can handle.
    ///
    /// <!-- inputs/outputs -->
    ///   @param file a pointer to the elf file
    ///   @return Returns 0 on success or an error code on failure.
    ///
    [[nodiscard]] constexpr auto
    validate_elf64_ehdr(bsl::span<bsl::uint8 const> const &file) noexcept -> bsl::errc_type
    {
        auto const *const ehdr{get_elf64_ehdr(file)};
        if (nullptr == ehdr) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        if (*ehdr->e_ident.at_if(EI_MAG0) != ELFMAG0) {
            bsl::error() << "invalid ELF magic number\n" << bsl::here();
            return bsl::errc_failure;
        }

        if (*ehdr->e_ident.at_if(EI_MAG1) != ELFMAG1) {
            bsl::error() << "invalid ELF magic number\n" << bsl::here();
            return bsl::errc_failure;
        }

        if (*ehdr->e_ident.at_if(EI_MAG2) != ELFMAG2) {
            bsl::error() << "invalid ELF magic number\n" << bsl::here();
            return bsl::errc_failure;
        }

        if (*ehdr->e_ident.at_if(EI_MAG3) != ELFMAG3) {
            bsl::error() << "invalid ELF magic number\n" << bsl::here();
            return bsl::errc_failure;
        }

        if (*ehdr->e_ident.at_if(EI_CLASS) != ELFCLASS64) {
            bsl::error() << "invalid ELF class\n" << bsl::here();
            return bsl::errc_failure;
        }

        if (*ehdr->e_ident.at_if(EI_OSABI) != ELFOSABI_SYSV) {
            bsl::error() << "invalid ELF OSABI\n" << bsl::here();
            return bsl::errc_failure;
        }

        if (ehdr->e_type != ET_EXEC) {
            bsl::error() << "invalid ELF type\n" << bsl::here();
            return bsl::errc_failure;
        }

        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief Returns the ELF entry point given an ELF file, or
    ///     bsl::safe_uintmax::failure() if a entry point does not exist or
    ///     a failure occurs.
    ///
    /// <!-- inputs/outputs -->
    ///   @param file the ELF file to get the ELF entry point from
    ///   @return Returns the ELF entry point given an ELF file, or
    ///     bsl::safe_uintmax::failure() if a entry point does not exist or
    ///     a failure occurs.
    ///
    [[nodiscard]] constexpr auto
    get_elf64_ip(bsl::span<bsl::uint8 const> const &file) noexcept -> bsl::safe_uintmax
    {
        return get_elf64_ehdr(file)->e_entry;
    }
}

#pragma pack(pop)

#endif
