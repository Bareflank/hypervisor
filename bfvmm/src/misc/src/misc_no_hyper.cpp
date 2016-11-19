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

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <debug_ring/debug_ring.h>
#include <serial/serial_port_intel_x64.h>

debug_ring *dr = nullptr;

extern "C" int
write(int file, const void *buffer, size_t count)
{
    (void) file;

    if (buffer == nullptr || count == 0)
        return 0;

    try
    {
        auto str = std::string(static_cast<const char *>(buffer), count);

        if (dr == nullptr)
            dr = new debug_ring(0);

        dr->write(str);
        serial_port_intel_x64::instance()->write(str);
        return static_cast<int>(count);
    }
    catch (...) { }

    return 0;
}

extern "C" int64_t
start_vmm(uint64_t arg) noexcept
{
    (void) arg;

    auto msg = "start_vmm\n";
    write(1, msg, strlen(msg));

    return 0;
}

extern "C" int64_t
stop_vmm(uint64_t arg) noexcept
{
    (void) arg;

    auto msg = "stop_vmm\n";
    write(1, msg, strlen(msg));

    return 0;
}

extern "C" int
fstat(int file, struct stat *sbuf)
{
    (void) file;
    (void) sbuf;

    errno = -ENOSYS;
    return -1;
}

extern "C" void
__stack_chk_fail(void) noexcept
{
    auto msg = "__stack_chk_fail: buffer overflow detected!!!\n";
    write(1, msg, strlen(msg));
    abort();
}
