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

#include <debug/debug_ring/debug_ring.h>
#include <debug/serial/serial_ns16550a.h>
#include <debug/serial/serial_pl011.h>

#include <mutex>
std::mutex g_write_mutex;

extern "C" EXPORT_SYM void
unlock_write(void)
{ g_write_mutex.unlock(); }

static auto
g_debug_ring() noexcept
{
    static bfvmm::debug_ring dr{vcpuid::invalid};
    return &dr;
}

extern "C" EXPORT_SYM uint64_t
write_str(const std::string &str)
{
    try {
        std::lock_guard<std::mutex> guard(g_write_mutex);

        g_debug_ring()->write(str);

        for (const auto &c : str) {
            bfvmm::DEFAULT_COM_DRIVER::instance()->write(c);
        }
    }
    catch (...) {
        return 0;
    }

    return str.length();
}

extern "C" EXPORT_SYM uint64_t
unsafe_write_cstr(const char *cstr, size_t len)
{
    try {
        auto str = gsl::make_span(cstr, gsl::narrow_cast<std::ptrdiff_t>(len));

        for (const auto &c : str) {
            bfvmm::DEFAULT_COM_DRIVER::instance()->write(c);
        }
    }
    catch (...) {
        return 0;
    }

    return len;
}

extern "C" EXPORT_SYM int
write(int __fd, const void *__buf, size_t __nbyte)
{
    if (__buf == nullptr || __nbyte == 0) {
        return 0;
    }

    if (__fd != 1 && __fd != 2) {
        return 0;
    }

    return gsl::narrow_cast<int>(write_str(std::string(static_cast<const char *>(__buf), __nbyte)));
}
