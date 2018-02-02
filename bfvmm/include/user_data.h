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

#ifndef USER_DATA_H
#define USER_DATA_H

namespace bfvmm
{

/// User Data
///
/// This defines the base class used for passing around user data.
/// This is mainly used so that dynamic_cast can be used if desired
/// for casting user data.
///
class user_data
{
public:

    /// Default Constructor
    ///
    user_data() = default;

    /// Default Destructor
    ///
    virtual ~user_data() = default;

public:

    /// @cond

    user_data(user_data &&) noexcept = delete;
    user_data &operator=(user_data &&) noexcept = delete;

    user_data(const user_data &) = delete;
    user_data &operator=(const user_data &) = delete;

    /// @endcond
};

}

#endif
