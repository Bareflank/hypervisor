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

#ifndef PAGE_POOL_HELPERS_HPP
#define PAGE_POOL_HELPERS_HPP

#include <basic_page_pool_node_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/discard.hpp>

namespace helpers
{
    /// <!-- description -->
    ///   @brief Adds more pages to the page_pool_t and returns the new head.
    ///     If no pages can be added to the pool, a nullptr is returned.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam SYS_T the type of bf_syscall_t to use
    ///   @param mut_sys (optional) the bf_syscall_t to use
    ///   @return Returns the new head of the page_pool_t on success. On failure,
    ///     a nullptr is returned.
    ///
    template<typename SYS_T>
    [[nodiscard]] constexpr auto
    add_to_page_pool(SYS_T &mut_sys) noexcept -> lib::basic_page_pool_node_t *
    {
        bsl::discard(mut_sys);

        bsl::error() << "page pool out of pages\n" << bsl::here();
        return nullptr;
    }
}

#endif
