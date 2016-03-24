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

#ifndef EXIT_HANDLER_INTEL_X64_EXCEPTIONS_H
#define EXIT_HANDLER_INTEL_X64_EXCEPTIONS_H

#include <exception.h>

namespace bfn
{

// -----------------------------------------------------------------------------
// Exit Handler Read Failure
// -----------------------------------------------------------------------------

class exit_handler_read_failure_error : public bfn::general_exception
{
public:
    exit_handler_read_failure_error(uint64_t field,
                                    const std::string &func,
                                    uint64_t line) :
        m_field(field),
        m_func(func),
        m_line(line)
    {}

    virtual std::ostream &print(std::ostream &os) const
    {
        os << "vmcs read failure:";
        os << std::endl << "    - field: " << (void *)m_field;
        os << std::endl << "    - func: " << m_func;
        os << std::endl << "    - line: " << m_line;

        return os;
    }

private:
    uint64_t m_field;
    std::string m_func;
    uint64_t m_line;
};

#define exit_handler_read_failure(a) \
    bfn::exit_handler_read_failure_error(a,__func__,__LINE__)

// -----------------------------------------------------------------------------
// Exit Handler Write Failure
// -----------------------------------------------------------------------------

class exit_handler_write_failure_error : public bfn::general_exception
{
public:
    exit_handler_write_failure_error(uint64_t field,
                                     uint64_t value,
                                     const std::string &func,
                                     uint64_t line) :
        m_field(field),
        m_value(value),
        m_func(func),
        m_line(line)
    {}

    virtual std::ostream &print(std::ostream &os) const
    {
        os << "vmcs write failure:";
        os << std::endl << "    - field: " << (void *)m_field;
        os << std::endl << "    - value: " << (void *)m_value;
        os << std::endl << "    - func: " << m_func;
        os << std::endl << "    - line: " << m_line;

        return os;
    }

private:
    uint64_t m_field;
    uint64_t m_value;
    std::string m_func;
    uint64_t m_line;
};

#define exit_handler_write_failure(a,b) \
    bfn::exit_handler_write_failure_error(a,b,__func__,__LINE__)

}

#endif
