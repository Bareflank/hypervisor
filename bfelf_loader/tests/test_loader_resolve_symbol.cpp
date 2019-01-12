//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-reinterpret-cast
//
// Reason:
//     Although in general this is a good rule, for hypervisor level code that
//     interfaces with the kernel, and raw hardware, this rule is
//     impractical.
//

#include <catch/catch.hpp>
#include <test_real_elf.h>

using func_t = void (*)();

TEST_CASE("bfelf_loader_resolve_symbol: invalid loader")
{
    func_t func;

    auto ret = bfelf_loader_resolve_symbol(nullptr, "lib1_foo", reinterpret_cast<void **>(&func));
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_loader_resolve_symbol: invalid name")
{
    func_t func;
    bfelf_loader_t loader = {};

    auto ret = bfelf_loader_resolve_symbol(&loader, nullptr, reinterpret_cast<void **>(&func));
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_loader_resolve_symbol: invalid addr")
{
    bfelf_loader_t loader = {};

    auto ret = bfelf_loader_resolve_symbol(&loader, "lib1_foo", nullptr);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_loader_resolve_symbol: no files added")
{
    int64_t ret = 0;
    bfelf_loader_t loader = {};

    ret = bfelf_loader_relocate(&loader);
    CHECK(ret == BFELF_SUCCESS);

    func_t func;

    ret = bfelf_loader_resolve_symbol(&loader, "lib1_foo", reinterpret_cast<void **>(&func));
    CHECK(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

TEST_CASE("bfelf_loader_resolve_symbol: no such symbol")
{
    int64_t ret = 0;
    binaries_info binaries{&g_file, g_filenames};

    func_t func;

    ret = bfelf_loader_resolve_symbol(&binaries.loader(), "invalid_sym", reinterpret_cast<void **>(&func));
    CHECK(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

TEST_CASE("bfelf_loader_resolve_symbol: success")
{
    int64_t ret = 0;
    binaries_info binaries{&g_file, g_filenames};

    func_t func;

    ret = bfelf_loader_resolve_symbol(&binaries.loader(), "lib1_foo", reinterpret_cast<void **>(&func));
    CHECK(ret == BFELF_SUCCESS);
}

TEST_CASE("bfelf_loader_resolve_symbol: no such symbol no hash")
{
    int64_t ret = 0;
    binaries_info binaries{&g_file, g_filenames};

    binaries.ef(0).hash = nullptr;
    binaries.ef(1).hash = nullptr;

    func_t func;

    ret = bfelf_loader_resolve_symbol(&binaries.loader(), "invalid_sym", reinterpret_cast<void **>(&func));
    CHECK(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

TEST_CASE("bfelf_loader_resolve_symbol: success no hash")
{
    int64_t ret = 0;
    binaries_info binaries{&g_file, g_filenames};

    binaries.ef(0).hash = nullptr;
    binaries.ef(1).hash = nullptr;

    func_t func;

    ret = bfelf_loader_resolve_symbol(&binaries.loader(), "lib1_foo", reinterpret_cast<void **>(&func));
    CHECK(ret == BFELF_SUCCESS);
}
