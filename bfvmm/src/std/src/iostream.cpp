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

#include <std/iostream>

#include <std/stdlib.h>
#include <std/string.h>
#include <entry/entry_factory.h>

// =============================================================================
// Globals
// =============================================================================

namespace std
{
    bfostream cout;
}

// =============================================================================
// Implementation
// =============================================================================

namespace std
{
    void
    bfostream::init()
    {
        auto serial = ef()->get_serial_port();
        serial->open();

        m_base = 10;
        m_width = 0;
        m_justify = std::left;
    }

    ostream &
    ostream::operator<<(const char *str)
    {
        int len = strlen(str);
        int gap = m_width - len;

        if (m_width > 0)
            m_width = 0;

        // TODO: We need to add multi-core support here. To do that, this code
        //       will have to lookup the CPU that it's running on to know which
        //       debug ring to dump the text to

        // TODO: There are a lot of train wrecks in the code here that
        //       need to be removed.

        auto vc = ef()->get_vcpu_factory()->get_vcpu(0);
        auto serial = ef()->get_serial_port();

        if (vc == 0 || serial == 0)
            return *this;

        if (m_justify == std::right)
        {
            for (auto i = 0; i < gap; i++)
            {
                *serial << ' ';
                vc->get_debug_ring()->write(" ", 1);
            }
        }

        *serial << str;
        vc->get_debug_ring()->write(str, len);

        if (m_justify == std::left)
        {
            for (auto i = 0; i < gap; i++)
            {
                *serial << ' ';
                vc->get_debug_ring()->write(" ", 1);
            }
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
    ostream::operator<<(unsigned char val)
    {
        unsigned char str[2] = {val, '\0'};
        return *this << str;
    }

    ostream &
    ostream::operator<<(short val)
    {
        char str[IOTA_MIN_BUF_SIZE];
        return *this << itoa(val, str, m_base);
    }

    ostream &
    ostream::operator<<(unsigned short val)
    {
        char str[IOTA_MIN_BUF_SIZE];
        return *this << itoa(val, str, m_base);
    }

    ostream &
    ostream::operator<<(int val)
    {
        char str[IOTA_MIN_BUF_SIZE];
        return *this << itoa(val, str, m_base);
    }

    ostream &
    ostream::operator<<(unsigned int val)
    {
        char str[IOTA_MIN_BUF_SIZE];
        return *this << itoa(val, str, m_base);
    }

    ostream &
    ostream::operator<<(long long int val)
    {
        char str[IOTA_MIN_BUF_SIZE];
        return *this << itoa(val, str, m_base);
    }

    ostream &
    ostream::operator<<(unsigned long long int val)
    {
        char str[IOTA_MIN_BUF_SIZE];
        return *this << itoa(val, str, m_base);
    }

    ostream &
    ostream::operator<<(void *val)
    {
        char str[IOTA_MIN_BUF_SIZE];
        return *this << "0x" << itoa((uint64_t)val, str, 16);
    }

    ostream &
    ostream::operator<<(size_t val)
    {
        char str[IOTA_MIN_BUF_SIZE];
        return *this << itoa(val, str, m_base);
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
    }

    ostream_width
    setw(int width)
    {
        return std::ostream_width(width);
    }
}
