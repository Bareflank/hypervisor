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

#include <crt.h>

#include <stddef.h>
#include <stdint.h>
#include <memory.h>

extern "C" int64_t
start_vmm(uint64_t arg) noexcept
{ (void) arg; return 0; }

extern "C" int64_t
stop_vmm(uint64_t arg) noexcept
{ (void) arg; return 0; }

extern "C" int
write(int file, const void *buffer, size_t count)
{
    (void) file;
    (void) buffer;
    (void) count;

    return 0;
}

extern "C" void
__cxa_end_catch(void)
{ }

extern "C" void
__cxa_begin_catch(void)
{ }

extern "C" void
__gxx_personality_v0(void)
{ }

namespace std
{
void terminate()
{ }
}

extern "C" int64_t
add_md(memory_descriptor *md) noexcept
{ (void) md; return 0; }

extern "C" void *
memset(void *block, int c, size_t size)
{
    auto dstp = static_cast<unsigned char *>(block);

    for (auto i = 0UL; i < size; i++)
        dstp[i] = static_cast<unsigned char>(c);

    return block;
}

extern "C" int64_t
local_init(struct section_info_t *info)
{ (void) info; return CRT_SUCCESS; }

extern "C" int64_t
local_fini(struct section_info_t *info)
{ (void) info; return CRT_SUCCESS; }
