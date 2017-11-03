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
#include <serial/serial_port_base.h>

void
serial_port_base::write(const std::string &str) noexcept
{
    for (auto c : str) {
        this->write(c);
    }
}

void
serial_port_base::write(const char *str, size_t len) noexcept
{
    gsl::cstring_span<> span(str, gsl::narrow_cast<std::ptrdiff_t>(len));

    for (auto c : span) {
        this->write(c);
    }
}

serial_port_base::value_type_8
serial_port_base::offset_inb(serial_port_base::port_type offset) const noexcept
{
#if defined(BF_X64)
    return x64::portio::inb(gsl::narrow_cast<port_type>(port() + offset));
#elif defined(BF_AARCH64)
    auto ptr = reinterpret_cast<uint8_t volatile *>(port() + offset);
    return *ptr;
#endif
}

serial_port_base::value_type_32
serial_port_base::offset_ind(serial_port_base::port_type offset) const noexcept
{
#if defined(BF_X64)
    return x64::portio::ind(gsl::narrow_cast<port_type>(port() + offset));
#elif defined(BF_AARCH64)
    auto ptr = reinterpret_cast<uint32_t volatile *>(port() + offset);
    return *ptr;
#endif
}

void
serial_port_base::offset_outb(serial_port_base::port_type offset, serial_port_base::value_type_8 data) const noexcept
{
#if defined(BF_X64)
    x64::portio::outb(gsl::narrow_cast<port_type>(port() + offset),
                      gsl::narrow_cast<value_type_8>(data));
#elif defined(BF_AARCH64)
    auto ptr = reinterpret_cast<uint8_t volatile *>(port() + offset);
    *ptr = data;
#endif
}

void
serial_port_base::offset_outd(serial_port_base::port_type offset, serial_port_base::value_type_32 data) const noexcept
{
#if defined(BF_X64)
    x64::portio::outd(gsl::narrow_cast<port_type>(port() + offset),
                      gsl::narrow_cast<value_type_32>(data));
#elif defined(BF_AARCH64)
    auto ptr = reinterpret_cast<uint32_t volatile *>(port() + offset);
    *ptr = data;
#endif
}
