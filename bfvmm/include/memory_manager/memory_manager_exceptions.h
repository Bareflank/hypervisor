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

#ifndef MEMORY_MANAGER_EXCEPTIONS_H
#define MEMORY_MANAGER_EXCEPTIONS_H

#include <exception.h>

namespace bfn
{

// -----------------------------------------------------------------------------
// Invalid MDL
// -----------------------------------------------------------------------------

class invalid_mdl_error : public bfn::general_exception
{
public:
    invalid_mdl_error(const std::string &mesg, uint64_t index) :
        m_mesg(mesg),
        m_index(index)
    {}

    virtual std::ostream &print(std::ostream &os) const
    { return os << "invalid mdl [" << m_index << "]: " << m_mesg; }

private:
    std::string m_mesg;
    uint64_t m_index;
};

#define invalid_mdl(a,b) bfn::invalid_mdl_error(a,b)

}

#endif
