//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <hippomocks.h>
#include <catch/catch.hpp>

#include <bfgsl.h>
#include <bfplatform.h>

#include <list>
#include <fstream>
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

        gsl::at(binaries, i).file = file.data();
        gsl::at(binaries, i).file_size = file.size();

        files.emplace_back(std::move(file));
    }

    gsl::at(const_cast<char *>(gsl::at(binaries, 0).file), 16, 0) = 0;

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

        gsl::at(binaries, i).file = file.data();
        gsl::at(binaries, i).file_size = file.size();

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

        gsl::at(binaries, i).file = file.data();
        gsl::at(binaries, i).file_size = file.size();

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
    bfelf_binary_t binaries[9] = {};

    std::list<bfn::buffer> files;
    for (auto i = 0ULL; i < 9; i++) {
        auto file = g_file.read_binary(g_filenames.at(i));

        gsl::at(binaries, i).file = file.data();
        gsl::at(binaries, i).file_size = file.size();

        files.emplace_back(std::move(file));
    }

    auto ret = bfelf_load(reinterpret_cast<bfelf_binary_t *>(binaries), 9, &entry, &info, &loader);
    CHECK(ret == BF_SUCCESS);
}
