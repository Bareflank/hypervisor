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

///
/// @file bfobject.h
///

#ifndef BFOBJECT_H
#define BFOBJECT_H

/// User Data
///
/// This defines the base class used for passing around subclasses.
/// This is mainly used so that dynamic_cast can be used if desired
/// for casting and deletion.
///
class bfobject
{
public:

    /// Default Constructor
    ///
    bfobject() = default;

    /// Default Destructor
    ///
    virtual ~bfobject() = default;

public:

    /// @cond

    bfobject(bfobject &&) noexcept = delete;
    bfobject &operator=(bfobject &&) noexcept = delete;

    bfobject(const bfobject &) = delete;
    bfobject &operator=(const bfobject &) = delete;

    /// @endcond
};

#endif
