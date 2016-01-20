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

#include <std/stdlib.h>
#include <std/string.h>

#include <std/iostream>
#include <vcpu/vcpu_manager.h>
#include <serial/serial_port_x86.h>

// =============================================================================
// Globals
// =============================================================================

namespace std
{
    ostream cout;
}

serial_port_x86 *
internal_serial()
{
    static serial_port_x86 serial;
    return &serial;
}

bool
write(const char *str, int64_t len)
{
    // TODO: The "-1" is a placeholder for now. At some point, we need to add
    // a custom iostream target that is capable of changing which CPU the
    // cout goes to.

    g_vcm->write(-1, str, len);
    internal_serial()->write(str, len);

    return true;
}

// =============================================================================
// Implementation
// =============================================================================

namespace std
{
    ostream::ostream() :
        m_base(10),
        m_width(0),
        m_justify(std::left)
    {
        internal_serial()->open();
        internal_serial()->write("serial: open\n");
    }

    ostream::~ostream()
    {
        internal_serial()->write("serial: closed\n");
        internal_serial()->close();
    }

    ostream &
    ostream::operator<<(const char *str)
    {
        int len = bfstrlen(str);
        int gap = m_width - len;

        if (m_width > 0)
            m_width = 0;

        if (m_justify == std::right)
        {
            for (auto i = 0; i < gap; i++)
                write(" ", 1);
        }

        write(str, len);

        if (m_justify == std::left)
        {
            for (auto i = 0; i < gap; i++)
                write(" ", 1);
        }

        return *this;
    }

    ostream &
    ostream::operator<<(bool val)
    {
        if (val == true)
            return *this << "true";
        else
            return *this << "false";
    }

    ostream &
    ostream::operator<<(char val)
    {
        char str[2] = {val, '\0'};
        return *this << str;
    }

    ostream &
    ostream::operator<<(void *val)
    {
        char str[IOTA_MIN_BUF_SIZE];
        return *this << "0x" << bfitoa((uint64_t)val, str, 16);
    }

    ostream &
    ostream::operator<<(int8_t val)
    {
        char str[IOTA_MIN_BUF_SIZE];
        return *this << bfitoa(val, str, m_base);
    }

    ostream &
    ostream::operator<<(uint8_t val)
    {
        char str[IOTA_MIN_BUF_SIZE];
        return *this << bfitoa(val, str, m_base);
    }

    ostream &
    ostream::operator<<(int16_t val)
    {
        char str[IOTA_MIN_BUF_SIZE];
        return *this << bfitoa(val, str, m_base);
    }

    ostream &
    ostream::operator<<(uint16_t val)
    {
        char str[IOTA_MIN_BUF_SIZE];
        return *this << bfitoa(val, str, m_base);
    }

    ostream &
    ostream::operator<<(int32_t val)
    {
        char str[IOTA_MIN_BUF_SIZE];
        return *this << bfitoa(val, str, m_base);
    }

    ostream &
    ostream::operator<<(uint32_t val)
    {
        char str[IOTA_MIN_BUF_SIZE];
        return *this << bfitoa(val, str, m_base);
    }

    ostream &
    ostream::operator<<(int64_t val)
    {
        char str[IOTA_MIN_BUF_SIZE];
        return *this << bfitoa(val, str, m_base);
    }

    ostream &
    ostream::operator<<(uint64_t val)
    {
        char str[IOTA_MIN_BUF_SIZE];
        return *this << bfitoa(val, str, m_base);
    }

    ostream &
    ostream::operator<<(ostream_modifier modifier)
    {
        switch (modifier)
        {
            case std::endl:
                return *this << "\r\n";

            case std::dec:
                m_base = 10;
                break;

            case std::hex:
                m_base = 16;
                break;

            case std::left:
                m_justify = std::left;
                break;

            case std::right:
                m_justify = std::right;
                break;

            default:
                break;
        };

        return *this;
    }

    ostream &
    ostream::operator<<(ostream_width width)
    {
        m_width = width.val();
        return *this;
    }

    ostream_width
    setw(int width)
    {
        return std::ostream_width(width);
    }
}
