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
    VMM_PREFIX_PATH + "/lib/libdummy_lib1.a"_s,
    VMM_PREFIX_PATH + "/lib/libdummy_lib2.a"_s,
    VMM_PREFIX_PATH + "/lib/libbfpthread.a"_s,
    VMM_PREFIX_PATH + "/lib/libbfsyscall.a"_s,
    VMM_PREFIX_PATH + "/lib/libbfunwind.a"_s,
    VMM_PREFIX_PATH + "/bin/dummy_main"_s
};

file g_file;
bool out_of_memory = false;
static std::map<const void *, std::shared_ptr<char>> g_memory;

extern "C" void *
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

extern "C" void
platform_free_rwe(void *addr, uint64_t len)
{
    bfignored(len);
    g_memory.erase(addr);
}

extern "C" void *
platform_memset(void *ptr, char value, uint64_t num)
{ return memset(ptr, value, num); }

extern "C" int64_t
platform_memcpy(
    void *dst, uint64_t dst_size, const void *src, uint64_t src_size, uint64_t num)
{
    bfignored(dst_size);
    bfignored(src_size);

    memcpy(dst, src, num);
    return SUCCESS;
}
