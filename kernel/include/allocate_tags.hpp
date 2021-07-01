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

#ifndef ALLOCATE_TAGS_HPP
#define ALLOCATE_TAGS_HPP

#include <bsl/cstr_type.hpp>

namespace mk
{
    /// @brief Defines the "bf_mem_op_alloc_page" tag
    constexpr auto ALLOCATE_TAG_BF_MEM_OP_ALLOC_PAGE{"bf_mem_op_alloc_page"};
    /// @brief Defines the "bf_mem_op_alloc_heap" tag
    constexpr auto ALLOCATE_TAG_BF_MEM_OP_ALLOC_HEAP{"bf_mem_op_alloc_heap"};
    /// @brief Defines the "extension stack memory" tag
    constexpr auto ALLOCATE_TAG_EXT_STACK{"extension stack memory"};
    /// @brief Defines the "extension TLS memory" tag
    constexpr auto ALLOCATE_TAG_EXT_TLS{"extension TLS memory"};
    /// @brief Defines the "extension TCB memory" tag
    constexpr auto ALLOCATE_TAG_EXT_TCB{"extension TCB memory"};
    /// @brief Defines the "extension ELF segments" tag
    constexpr auto ALLOCATE_TAG_EXT_ELF{"extension ELF segments"};
    /// @brief Defines the "pml4ts" tag
    constexpr auto ALLOCATE_TAG_PML4TS{"pml4ts"};
    /// @brief Defines the "pdpts" tag
    constexpr auto ALLOCATE_TAG_PDPTS{"pdpts"};
    /// @brief Defines the "pdts" tag
    constexpr auto ALLOCATE_TAG_PDTS{"pdts"};
    /// @brief Defines the "pts" tag
    constexpr auto ALLOCATE_TAG_PTS{"pts"};
    /// @brief Defines the "guest vmcb" tag
    constexpr auto ALLOCATE_TAG_GUEST_VMCB{"guest vmcb"};
    /// @brief Defines the "host vmcb" tag
    constexpr auto ALLOCATE_TAG_HOST_VMCB{"host vmcb"};
    /// @brief Defines the "vmcs" tag
    constexpr auto ALLOCATE_TAG_VMCS{"vmcs"};
}

#endif
