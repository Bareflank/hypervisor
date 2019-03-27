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

#include <bfgsl.h>
#include <bfexports.h>

#include <debug/debug_ring/debug_ring.h>
#include <debug/serial/serial_ns16550a.h>
#include <debug/serial/serial_pl011.h>

#include <mutex>
std::mutex g_write_mutex;

extern "C" void
unlock_write(void)
{ g_write_mutex.unlock(); }

static auto
g_debug_ring() noexcept
{
    static bfvmm::debug_ring dr{vcpuid::invalid};
    return &dr;
}

extern "C" uint64_t
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

extern "C" uint64_t
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

extern "C" int
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
