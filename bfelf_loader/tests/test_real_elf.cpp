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

// TIDY_EXCLUSION=-cert-err58-cpp
//
// Reason:
//     This triggers on g_filenames which is only used for testing. This
//     is not a false positive, but it can be safely ignored.
//

// TIDY_EXCLUSION=-cppcoreguidelines-owning-memory
//
// Reason:
//     This triggers during the allocation which is part of the test harness
//     so this can be safely ignored.
//

#include <test_real_elf.h>

#include <map>
#include <list>
#include <vector>

#ifdef WIN64
#include <windows.h>
#else
#include <sys/mman.h>
#endif

std::vector<std::string> g_filenames = {
    VMM_PREFIX_PATH + "/lib/libdummy_lib1_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libdummy_lib2_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libc++.so.1.0"_s,
    VMM_PREFIX_PATH + "/lib/libc++abi.so"_s,
    VMM_PREFIX_PATH + "/lib/libc.so"_s,
    VMM_PREFIX_PATH + "/lib/libm.so"_s,
    VMM_PREFIX_PATH + "/lib/libbfpthread_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libbfsyscall_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libbfunwind_shared.so"_s,
    VMM_PREFIX_PATH + "/bin/dummy_main_shared"_s
};

file g_file;
bool out_of_memory = false;
static std::map<const void *, std::shared_ptr<char>> g_memory;

void *
platform_alloc_rwe(uint64_t len)
{
    if (out_of_memory) {
        return nullptr;
    }

    auto addr = aligned_alloc(0x1000, len);
    g_memory[addr] = std::shared_ptr<char>(static_cast<char *>(addr), free);

#ifdef WIN64
    DWORD oldProtect;
    VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &oldProtect);
#else
    mprotect(addr, len, PROT_READ | PROT_WRITE | PROT_EXEC);
#endif

    return addr;
}

void
platform_free_rwe(const void *addr, uint64_t len)
{
    bfignored(len);
    g_memory.erase(addr);
}

void *
platform_memset(void *ptr, char value, uint64_t num)
{ return memset(ptr, value, num); }

void *
platform_memcpy(void *dst, const void *src, uint64_t num)
{ return memcpy(dst, src, num); }
