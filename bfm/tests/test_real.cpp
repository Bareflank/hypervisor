//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#define CATCH_CONFIG_MAIN
#include <catch/catch.hpp>

#include <bfelf_loader.h>
#include <test_real_elf.h>

std::vector<char>fake_stack(0x8000);
using func_t = int (*)(char *stack, crt_info_t *);

TEST_CASE("bfelf_loader_resolve_symbol: real test")
{
    auto ret = 0LL;
    bfelf_loader_t loader = {};

    auto &&details = load_libraries(&loader, g_filenames);

    ret = bfelf_loader_relocate(&loader);
    CHECK(ret == BFELF_SUCCESS);

    crt_info_t crt_info = {};
    std::array<const char *, 2> argv{{"1000", "2000"}};

    crt_info.argc = 2;
    crt_info.argv = argv.data();

    for (auto &detail : details) {
        auto &&ef = std::get<0>(detail);
        section_info_t section_info = {};

        ret = bfelf_file_get_section_info(&ef, &section_info);
        CHECK(ret == BFELF_SUCCESS);

        crt_info.info[crt_info.info_num++] = section_info;
    }

    func_t func;
    auto &&dummy_main = details.back();

    ret = bfelf_file_get_entry(&dummy_main.first, reinterpret_cast<void **>(&func));
    CHECK(ret == BFELF_SUCCESS);

    CHECK(func(&fake_stack.at(0x7999), &crt_info) == 6000);
}
