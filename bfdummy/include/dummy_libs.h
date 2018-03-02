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

#ifndef DUMMY_LIBS_H
#define DUMMY_LIBS_H

#include <stddef.h>
#include <stdint.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_DUMMY
#ifdef SHARED_DUMMY
#define EXPORT_DUMMY EXPORT_SYM
#else
#define EXPORT_DUMMY IMPORT_SYM
#endif
#else
#define EXPORT_DUMMY
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

/* @cond */

extern int global_var;

class EXPORT_DUMMY base
{
public:
    base() noexcept = default;
    virtual ~base() = default;

    virtual int
    foo(int) noexcept
    {
        return 0;
    }
};

class EXPORT_DUMMY derived1 : public base
{
public:
    derived1() noexcept;
    ~derived1() override;

    int
    foo(int arg) noexcept override;

private:
    int m_member{1000};
};

class EXPORT_DUMMY derived2 : public base
{
public:
    derived2() noexcept;
    ~derived2() override;

    int
    foo(int arg) noexcept override;

private:
    int m_member{2000};
};

/* @endcond */

#endif
