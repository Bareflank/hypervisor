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
#include <debug_ring/debug_ring.h>

// =============================================================================
// Globals
// =============================================================================

namespace std
{
    ostream cout;
}

// =============================================================================
// Implementation
// =============================================================================

namespace std
{

    void
    ostream::init()
    {
        m_base = 10;
    }

    ostream &
    ostream::operator<<(const char *str)
    {
        // debug_ring::instance().write(str, strlen(str));
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
    ostream::operator<<(ostream_modifier modifier)
    {
        switch (modifier)
        {
            case std::endl:
                return *this << "\n";

            case std::dec:
                m_base = 10;
                break;

            case std::hex:
                m_base = 16;
                break;

            default:
                break;
        };

        return *this;
    }

}
