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

#include <bfgsl.h>
#include <bfexports.h>

#include <bfvmm/debug/debug_ring/debug_ring.h>
#include <bfvmm/debug/serial/serial_port_ns16550a.h>

#include <mutex>
std::mutex g_write_mutex;

extern "C" EXPORT_SYM void
unlock_write(void)
{ g_write_mutex.unlock(); }

static auto
g_debug_ring() noexcept
{
    static debug_ring dr{vcpuid::invalid};
    return &dr;
}

extern "C" EXPORT_SYM uint64_t
write_str(const std::string &str)
{
    try {
        std::lock_guard<std::mutex> guard(g_write_mutex);

        g_debug_ring()->write(str);
        serial_port_ns16550a::instance()->write(str);

        return str.length();
    }
    catch (...) {
        return 0;
    }
}

extern "C" EXPORT_SYM int
write(int file, const void *buffer, size_t count)
{
    if (buffer == nullptr || count == 0) {
        return 0;
    }

    if (file != 1 && file != 2) {
        return 0;
    }

    return gsl::narrow_cast<int>(write_str(std::string(static_cast<const char *>(buffer), count)));
}
