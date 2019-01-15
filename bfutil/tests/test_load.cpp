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

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-const-cast
//
// Reason:
//     This is test code, and we need to use const_cast so that we can modify
//     our ELF file so that it looks bad. This can safely be ignored.
//

#include <hippomocks.h>
#include <catch/catch.hpp>

#include <bfgsl.h>
#include <bfplatform.h>

#include <list>
#include <test_real_elf.h>

TEST_CASE("bfelf_load: invalid binaries")
{
    void *entry = nullptr;
    crt_info_t info = {};
    bfelf_loader_t loader = {};

    auto ret = bfelf_load(nullptr, 9, &entry, &info, &loader);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_load: invalid num binaries")
{
    void *entry = nullptr;
    crt_info_t info = {};
    bfelf_loader_t loader = {};
    bfelf_binary_t binaries[9] = {};

    auto ret = bfelf_load(reinterpret_cast<bfelf_binary_t *>(binaries), 0, &entry, &info, &loader);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_load: invalid entry")
{
    crt_info_t info = {};
    bfelf_loader_t loader = {};
    bfelf_binary_t binaries[9] = {};

    auto ret = bfelf_load(reinterpret_cast<bfelf_binary_t *>(binaries), 9, nullptr, &info, &loader);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_load: invalid info")
{
    void *entry = nullptr;
    bfelf_loader_t loader = {};
    bfelf_binary_t binaries[9] = {};

    auto ret = bfelf_load(reinterpret_cast<bfelf_binary_t *>(binaries), 9, &entry, nullptr, &loader);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_load: invalid loader")
{
    void *entry = nullptr;
    crt_info_t info = {};
    bfelf_binary_t binaries[9] = {};

    auto ret = bfelf_load(reinterpret_cast<bfelf_binary_t *>(binaries), 9, &entry, &info, nullptr);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_load: init fail")
{
    void *entry = nullptr;
    crt_info_t info = {};
    bfelf_loader_t loader = {};
    bfelf_binary_t binaries[9] = {};

    std::list<bfn::buffer> files;
    for (auto i = 0ULL; i < 9; i++) {
        auto file = g_file.read_binary(g_filenames.at(i));

        gsl::at(binaries, static_cast<std::ptrdiff_t>(i)).file = file.data();
        gsl::at(binaries, static_cast<std::ptrdiff_t>(i)).file_size = file.size();

        files.emplace_back(std::move(file));
    }

    auto view = gsl::make_span(const_cast<char *>(gsl::at(binaries, 0).file), 16);
    view[0] = 0;


    auto ret = bfelf_load(reinterpret_cast<bfelf_binary_t *>(binaries), 9, &entry, &info, &loader);
    CHECK(ret == BFELF_ERROR_INVALID_SIGNATURE);
}

TEST_CASE("bfelf_load: out of memory fail")
{
    void *entry = nullptr;
    crt_info_t info = {};
    bfelf_loader_t loader = {};
    bfelf_binary_t binaries[9] = {};

    std::list<bfn::buffer> files;
    for (auto i = 0ULL; i < 9; i++) {
        auto file = g_file.read_binary(g_filenames.at(i));

        gsl::at(binaries, static_cast<std::ptrdiff_t>(i)).file = file.data();
        gsl::at(binaries, static_cast<std::ptrdiff_t>(i)).file_size = file.size();

        files.emplace_back(std::move(file));
    }

    out_of_memory = true;
    auto ___ = gsl::finally([&] {
        out_of_memory = false;
    });

    auto ret = bfelf_load(reinterpret_cast<bfelf_binary_t *>(binaries), 9, &entry, &info, &loader);
    CHECK(ret == BFELF_ERROR_OUT_OF_MEMORY);
}

TEST_CASE("bfelf_load: relocate fail")
{
    void *entry = nullptr;
    crt_info_t info = {};
    bfelf_loader_t loader = {};
    bfelf_binary_t binaries[9] = {};

    std::list<bfn::buffer> files;
    for (auto i = 0ULL; i < 9; i++) {
        auto file = g_file.read_binary(g_filenames.at(i));

        gsl::at(binaries, static_cast<std::ptrdiff_t>(i)).file = file.data();
        gsl::at(binaries, static_cast<std::ptrdiff_t>(i)).file_size = file.size();

        files.emplace_back(std::move(file));
    }

    auto ret = bfelf_load(reinterpret_cast<bfelf_binary_t *>(binaries), 8, &entry, &info, &loader);
    CHECK(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

TEST_CASE("bfelf_load: success")
{
    void *entry = nullptr;
    crt_info_t info = {};
    bfelf_loader_t loader = {};
    bfelf_binary_t binaries[10] = {};

    std::list<bfn::buffer> files;
    for (auto i = 0ULL; i < 10; i++) {
        auto file = g_file.read_binary(g_filenames.at(i));

        gsl::at(binaries, static_cast<std::ptrdiff_t>(i)).file = file.data();
        gsl::at(binaries, static_cast<std::ptrdiff_t>(i)).file_size = file.size();

        files.emplace_back(std::move(file));
    }

    auto ret = bfelf_load(reinterpret_cast<bfelf_binary_t *>(binaries), 10, &entry, &info, &loader);
    CHECK(ret == BF_SUCCESS);
}
