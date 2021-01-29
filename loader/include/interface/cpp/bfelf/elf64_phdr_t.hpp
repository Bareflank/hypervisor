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

#ifndef BFELF_ELF64_PHDR_T_HPP
#define BFELF_ELF64_PHDR_T_HPP

#include "elf64_ehdr_t.hpp"

#include <bsl/byte.hpp>
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

    /// @brief defines p_type for unused entry
    constexpr bsl::safe_uint32 PT_NULL{bsl::to_u32(0U)};
    /// @brief defines p_type for a loadable segment
    constexpr bsl::safe_uint32 PT_LOAD{bsl::to_u32(1U)};
    /// @brief defines p_type for dynamic linking tables
    constexpr bsl::safe_uint32 PT_DYNAMIC{bsl::to_u32(2U)};
    /// @brief defines p_type for the program interpreter path
    constexpr bsl::safe_uint32 PT_INTERP{bsl::to_u32(3U)};
    /// @brief defines p_type for note sections
    constexpr bsl::safe_uint32 PT_NOTE{bsl::to_u32(4U)};
    /// @brief defines p_type for reserved
    constexpr bsl::safe_uint32 PT_SHLIB{bsl::to_u32(5U)};
    /// @brief defines p_type for the program header table
    constexpr bsl::safe_uint32 PT_PHDR{bsl::to_u32(6U)};
    /// @brief defines p_type for the tls segment
    constexpr bsl::safe_uint32 PT_TLS{bsl::to_u32(7U)};
    /// @brief defines p_type for environment-specific use (lo)
    constexpr bsl::safe_uint32 PT_LOOS{bsl::to_u32(0x60000000U)};
    /// @brief defines p_type for the GNU stack segment
    constexpr bsl::safe_uint32 PT_GNU_STACK{bsl::to_u32(0x6474e551U)};
    /// @brief defines p_type for environment-specific use (hi)
    constexpr bsl::safe_uint32 PT_HIOS{bsl::to_u32(0x6FFFFFFFU)};
    /// @brief defines p_type for processor-specific use (lo)
    constexpr bsl::safe_uint32 PT_LOPROC{bsl::to_u32(0x70000000U)};
    /// @brief defines p_type for processor-specific use (hi)
    constexpr bsl::safe_uint32 PT_HIPROC{bsl::to_u32(0x7FFFFFFFU)};

    /// @brief defines p_flags for execute permissions
    constexpr bsl::safe_uint32 PF_X{bsl::to_u32(1U)};
    /// @brief defines p_flags for write permissions
    constexpr bsl::safe_uint32 PF_W{bsl::to_u32(2U)};
    /// @brief defines p_flags for read permissions
    constexpr bsl::safe_uint32 PF_R{bsl::to_u32(4U)};
    /// @brief defines p_flags for environment-specific use
    constexpr bsl::safe_uint32 PF_MASKOS{bsl::to_u32(0x00FF0000U)};
    /// @brief defines p_flags for environment-specific use
    constexpr bsl::safe_uint32 PF_MASKPROC{bsl::to_u32(0xFF000000U)};

    /// @struct elf64_phdr_t
    ///
    /// <!-- description -->
    ///   @brief In executable and shared object files, sections are grouped
    ///     into segments for loading. The program header table contains a
    ///     list of entries describing each segment.
    ///
    struct elf64_phdr_t final
    {
        /// @brief Type of segment
        bsl::uint32 p_type;
        /// @brief Segment attributes
        bsl::uint32 p_flags;
        /// @brief Offset in file
        bsl::uint64 p_offset;
        /// @brief Virtual address in memory
        bsl::uint64 p_vaddr;
        /// @brief Reserved
        bsl::uint64 p_paddr;
        /// @brief Size of segment in file
        bsl::uint64 p_filesz;
        /// @brief Size of segment in memory
        bsl::uint64 p_memsz;
        /// @brief Alignment of segment
        bsl::uint64 p_align;
    };

    /// <!-- description -->
    ///   @brief Returns a pointer to an ELF program header given an ELF file
    ///
    /// <!-- inputs/outputs -->
    ///   @param file the ELF file to get the ELF program header from
    ///   @return returns a pointer to the ELF program header, or nullptr
    ///     on error
    ///
    [[nodiscard]] constexpr auto
    get_elf64_phdrtab(bsl::span<bsl::byte const> const &file) noexcept
        -> bsl::span<elf64_phdr_t const>
    {
        auto const *const ehdr{get_elf64_ehdr(file)};
        if (nullptr == ehdr) {
            bsl::print<bsl::V>() << bsl::here();
            return {};
        }

        auto const phdrtab_as_bytes{
            file.subspan(ehdr->e_phoff, bsl::to_umax(ehdr->e_phnum) * sizeof(elf64_phdr_t))};
        if (phdrtab_as_bytes.empty()) {
            bsl::print<bsl::V>() << bsl::here();
            return {};
        }

        return bsl::as_t<elf64_phdr_t const>(phdrtab_as_bytes);
    }
}

#pragma pack(pop)

#endif
