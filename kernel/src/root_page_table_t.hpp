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

#ifndef ROOT_PAGE_TABLE_T_HPP
#define ROOT_PAGE_TABLE_T_HPP

#include "root_page_table_helpers.hpp"    // IWYU pragma: export

#include <basic_root_page_table_t.hpp>
#include <intrinsic_t.hpp>
#include <l0e_t.hpp>
#include <l1e_t.hpp>
#include <l2e_t.hpp>
#include <l3e_t.hpp>
#include <page_pool_t.hpp>
#include <tls_t.hpp>

namespace mk
{
    /// @brief defines the root_page_table_t used by the microkernel
    using root_page_table_t = lib::basic_root_page_table_t<
        tls_t,
        bsl::dontcare_t,
        page_pool_t,
        intrinsic_t,
        lib::l3e_t,
        lib::l2e_t,
        lib::l1e_t,
        lib::l0e_t>;
}

#endif
