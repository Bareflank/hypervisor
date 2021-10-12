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

#ifndef START_VMM_ARGS_T_HPP
#define START_VMM_ARGS_T_HPP

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/span.hpp>

#pragma pack(push, 1)

namespace loader
{
    /// @brief defines the IOCTL index for starting the VMM
    constexpr auto START_VMM_CMD{0xBF01_u32};

    /// @brief defines the type used for passing the ext ELF files
    using elf_file_type = bsl::span<bsl::uint8 const>;

    /// @brief defines the type used for passing the ext ELF files
    using ext_elf_files_type = bsl::array<elf_file_type, HYPERVISOR_MAX_EXTENSIONS.get()>;

    /// <!-- description -->
    ///   @brief Defines the information that a userspace application needs to
    ///     provide to start the VMM.
    ///
    struct start_vmm_args_t final
    {
        /// @brief set to HYPERVISOR_VERSION
        bsl::uint64 ver;

        /// @brief stores the number of pages the kernel should reserve for
        ///   the microkernel's page pool. If this is set to 0, the loader
        ///   will reserve the default number of pages.
        bsl::uint32 num_pages_in_page_pool;

        /// @brief reserved.
        bsl::uint32 reserved;

        /// @brief stores the ELF file associated with the microkernel
        elf_file_type mk_elf_file;
        /// @brief stores the ELF files associated with the extensions
        ext_elf_files_type ext_elf_files;
    };
}

#pragma pack(pop)

#endif
