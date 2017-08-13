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

#ifndef TEST_REAL_ELF_H
#define TEST_REAL_ELF_H

#include <bfelf_loader.h>

#include <deque>
#include <memory>

extern const std::vector<std::string> g_filenames;

std::pair<std::unique_ptr<char[]>, uint64_t>
get_real_elf(const std::string &filename);

std::pair<std::unique_ptr<char, decltype(free) *>, uint64_t>
get_elf_exec(bfelf_file_t *ef);

std::unique_ptr<char, decltype(free) *>
add_elf_to_loader(const std::string &filename, bfelf_file_t *ef, bfelf_loader_t *loader);

std::deque<std::pair<bfelf_file_t, std::unique_ptr<char, decltype(free) *>>>
load_libraries(bfelf_loader_t *loader, const std::vector<std::string> &filenames);

#endif
