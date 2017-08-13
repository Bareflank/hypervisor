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

#include <gsl/gsl>

#include <deque>
#include <vector>
#include <fstream>

#include <cstdint>
#include <cstring>

#include <sys/mman.h>

#include <bfupperlower.h>
#include <test_real_elf.h>

#ifdef WIN32
#include <windows.h>
#endif

const std::vector<std::string> g_filenames = {
    "/lib/libdummy_lib1.so",
    "/lib/libdummy_lib2.so",
    "/lib/libc.so",
    "/lib/libc++.so.1.0",
    "/lib/libc++abi.so",
    "/lib/libpthread.so",
    "/lib/libsyscall.so",
    "/lib/libbfunwind.so",
    "/bin/dummy_main"
};

std::pair<std::unique_ptr<char[]>, uint64_t>
get_real_elf(const std::string &filename)
{
    if (auto &&ifs = std::ifstream(filename, std::ifstream::ate)) {
        auto &&size = static_cast<uint64_t>(ifs.tellg());
        auto &&data = std::make_unique<char[]>(size);

        ifs.seekg(0);
        ifs.read(data.get(), static_cast<int64_t>(size));

        return {std::move(data), size};
    }

    throw std::runtime_error("get_real_elf: unable to open " + filename);
}

char *
alloc_exec(size_t size)
{
    auto addr = aligned_alloc(0x1000, size);
    memset(addr, 0, size);

#ifdef WIN32
    DWORD oldProtect;
    VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &oldProtect);
#else
    mprotect(addr, size, PROT_READ | PROT_WRITE | PROT_EXEC);
#endif

    return reinterpret_cast<char *>(addr);
}

std::pair<std::unique_ptr<char, decltype(free) *>, uint64_t>
get_elf_exec(bfelf_file_t *ef)
{
    auto &&total = static_cast<size_t>(bfelf_file_get_total_size(ef));
    auto &&num_segments = bfelf_file_get_num_load_instrs(ef);

    auto &&exec = std::unique_ptr<char, decltype(free) *>(alloc_exec(total), free);

    for (auto i = 0U; i < num_segments; i++) {
        bfelf_load_instr *instr = nullptr;

        auto &&ret = bfelf_file_get_load_instr(ef, i, &instr);
        (void)ret;

        auto &&exec_view = gsl::make_span(exec.get(), gsl::narrow_cast<std::ptrdiff_t>(total));
        auto &&file_view = gsl::make_span(ef->file, gsl::narrow_cast<std::ptrdiff_t>(ef->filesz));

        auto &&mindex = gsl::narrow_cast<std::ptrdiff_t>(instr->mem_offset);
        auto &&findex = gsl::narrow_cast<std::ptrdiff_t>(instr->file_offset);

        memcpy(&exec_view.at(mindex), &file_view.at(findex), instr->filesz);
    }

    return {std::move(exec), total};
}

std::unique_ptr<char, decltype(free) *>
add_elf_to_loader(const std::string &filename, bfelf_file_t *ef, bfelf_loader_t *loader)
{
    auto ret = 0LL;

    auto &&ef_data = get_real_elf(BAREFLANK_SYSROOT_PATH + filename);
    auto &&ef_buff = std::get<0>(ef_data);
    auto &&ef_size = std::get<1>(ef_data);

    ret = bfelf_file_init(ef_buff.get(), ef_size, ef);
    if (ret != BFELF_SUCCESS) {
        return std::unique_ptr<char, decltype(free) *>(nullptr, free);
    }

    auto &&ef_pair = get_elf_exec(ef);
    auto &&ef_exec = std::move(std::get<0>(ef_pair));

    ret = bfelf_loader_add(loader, ef, ef_exec.get(), ef_exec.get());
    if (ret != BFELF_SUCCESS) {
        return std::unique_ptr<char, decltype(free) *>(nullptr, free);
    }

    return std::move(ef_exec);
}

std::deque<std::pair<bfelf_file_t, std::unique_ptr<char, decltype(free) *>>>
load_libraries(bfelf_loader_t *loader, const std::vector<std::string> &filenames)
{
    std::deque<std::pair<bfelf_file_t, std::unique_ptr<char, decltype(free) *>>> results;

    for (const auto &filename : filenames) {
        results.push_back({{}, std::unique_ptr<char, decltype(free) *>(nullptr, free)});
        auto &&lib = results.back();
        lib.second = add_elf_to_loader(filename, &lib.first, loader);
    }

    return results;
}
