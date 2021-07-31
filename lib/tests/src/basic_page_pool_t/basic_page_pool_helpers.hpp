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

#ifndef MOCK_BASIC_PAGE_POOL_HELPERS_HPP
#define MOCK_BASIC_PAGE_POOL_HELPERS_HPP

#include <basic_page_pool_node_t.hpp>

namespace helpers
{
    /// <!-- description -->
    ///   @brief If return_nullptr_on_empty is false, returns the new head of
    ///     the page_pool_t on success. If return_nullptr_on_empty is true,
    ///     returns a nullptr.
    ///
    /// <!-- inputs/outputs -->
    ///   @param return_nullptr_on_empty tells the page pool to return a
    ///     nullptr on empty. Normally this would be a bf_syscall_t but the
    ///     page pool will take any type, so we use a bool during unit testing.
    ///   @return If return_nullptr_on_empty is false, returns the new head of
    ///     the page_pool_t on success. If return_nullptr_on_empty is true,
    ///     returns a nullptr.
    ///
    [[nodiscard]] constexpr auto
    add_to_page_pool(bool const &return_nullptr_on_empty) noexcept -> lib::basic_page_pool_node_t *
    {
        if (return_nullptr_on_empty) {
            return nullptr;
        }

        // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
        return new lib::basic_page_pool_node_t{};
    }
}

#endif
