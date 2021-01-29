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

#include "state_save_t.hpp"

#include <bsl/array.hpp>
#include <bsl/byte.hpp>
#include <bsl/convert.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/span.hpp>

#pragma pack(push, 1)

namespace loader
{
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
        /// @brief reserved
        bsl::uint16 reserved1;
        /// @brief stores the number of online pps
        bsl::uint16 online_pps;
        /// @brief reserved
        bsl::uint32 reserved2;
        /// @brief stores the location of the microkernel's state (0x008)
        state_save_t *mk_state;
        /// @brief stores the location of the root vp state (0x010)
        state_save_t *root_vp_state;
        /// @brief stores the location of the debug ring (0x018)
        debug_ring_t *debug_ring;
        /// @brief stores the location of the microkernel's ELF file
        bsl::span<bsl::byte const> mk_elf_file;
        /// @brief stores the location of the extension's ELF files
        bsl::array<bsl::span<bsl::byte const>, HYPERVISOR_MAX_EXTENSIONS> ext_elf_files;
        /// @brief stores the virtual address of the MK's RPT for this CPU
        void *rpt;
        /// @brief stores the physical address of the MK's RPT for this CPU
        bsl::uint64 rpt_phys;
        /// @brief stores the location of the microkernel's page pool
        bsl::span<bsl::byte> page_pool;
        /// @brief stores the starting location of the page pool's direct map
        bsl::uint64 page_pool_base_virt;
        /// @brief stores the location of the microkernel's huge pool
        bsl::span<bsl::byte> huge_pool;
        /// @brief stores the starting location of the huge pool's direct map
        bsl::uint64 huge_pool_base_virt;
    };

    namespace details
    {
        /// @brief defined the expected size of the mk_args_t struct
        constexpr bsl::safe_uintmax EXPECTED_MK_ARGS_T_SIZE{bsl::to_umax(HYPERVISOR_PAGE_SIZE)};

        /// Check to make sure the mk_args_t is the right size.
        static_assert(!(sizeof(mk_args_t) > EXPECTED_MK_ARGS_T_SIZE));
    }
}

#pragma pack(pop)

#endif
