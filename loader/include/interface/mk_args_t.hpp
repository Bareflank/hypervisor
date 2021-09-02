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

#ifndef MK_ARGS_T_HPP
#define MK_ARGS_T_HPP

#include <bfelf/elf64_ehdr_t.hpp>
#include <state_save_t.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/span.hpp>

#pragma pack(push, 1)

namespace mk
{
    /// @brief defines a prototype for l3e_t
    struct l3e_t;
}

namespace lib
{
    /// @brief defines a prototype for basic_page_table_t
    template<typename E>
    struct basic_page_table_t;
    /// @brief defines a prototype for basic_page_pool_node_t
    struct basic_page_pool_node_t;
    /// @brief defines a prototype for basic_page_4k_t
    struct basic_page_4k_t;
}

namespace loader
{
    /// @brief defines the element type for ext_elf_files
    using ext_elf_file_t = bfelf::elf64_ehdr_t;
    /// @brief defines the ext_elf_files type
    using ext_elf_files_t = bsl::array<ext_elf_file_t const *, HYPERVISOR_MAX_EXTENSIONS.get()>;

    /// @struct loader::mk_args_t
    ///
    /// <!-- description -->
    ///   @brief Defines the arguments sent to the _start function of the
    ///     microkernel. The microkernel will have it's own C++ version of this
    ///     struct that provides the actual types for each of the arguments as
    ///     it expects them.
    ///
    struct mk_args_t final
    {
        /// @brief stores the current ppid (0x000)
        bsl::uint16 ppid;
        /// @brief stores the number of online pps (0x002)
        bsl::uint16 online_pps;
        /// @brief reserved (0x004)
        bsl::uint32 reserved0;
        /// @brief stores the location of the microkernel's state (0x008)
        state_save_t *mk_state;
        /// @brief stores the location of the root vp state (0x010)
        state_save_t *root_vp_state;
        /// @brief stores the location of the debug ring (0x018)
        debug_ring_t *debug_ring;
        /// @brief reserved
        void const *reserved1;
        /// @brief stores the location of the extension's ELF files
        ext_elf_files_t ext_elf_files;
        /// @brief stores the virtual address of the MK's RPT for this CPU
        lib::basic_page_table_t<mk::l3e_t> *rpt;
        /// @brief stores the physical address of the MK's RPT for this CPU
        bsl::uint64 rpt_phys;
        /// @brief stores the location of the microkernel's page pool
        bsl::span<lib::basic_page_pool_node_t> page_pool;
        /// @brief stores the location of the microkernel's huge pool
        bsl::span<lib::basic_page_4k_t> huge_pool;
    };
}

#pragma pack(pop)

#endif
