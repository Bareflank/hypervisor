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

#ifndef ELF64_SHDR_T_HPP
#define ELF64_SHDR_T_HPP

#include <bsl/cstdint.hpp>

#pragma pack(push, 1)

namespace bfelf
{
    /// <!-- description -->
    ///   @brief Sections provide different information from relocation
    ///     instructions to strings stored in the executable.
    ///
    /// <!-- notes -->
    ///   @note IMPORTANT: If sections are ever actually needed, the offset
    ///     cannot actually be a byte array, but instead needs to be a union
    ///     of the different types that the section might actually be. This
    ///     is AUTOSAR compliant because the type field is the "tag", making
    ///     the union a tagged union which is allowed. This will ensure that
    ///     you can parse the different sections without having to do casts.
    ///
    struct elf64_shdr_t final
    {
        /// @brief name of section
        bsl::uint32 sh_name;
        /// @brief type of section
        bsl::uint32 sh_type;
        /// @brief section attributes
        bsl::uint32 sh_flags;
        /// @brief virtual address of section
        bsl::uint64 sh_addr;
        /// @brief offset of section in ELF file
        bsl::uint8 *sh_offset;
        /// @brief size of section
        bsl::uint32 sh_size;
        /// @brief section linked to this section
        bsl::uint32 sh_link;
        /// @brief section information
        bsl::uint32 sh_info;
        /// @brief section alignment
        bsl::uint32 sh_addralign;
        /// @brief size of section entries
        bsl::uint32 sh_entsize;
    };
}

#pragma pack(pop)

#endif
