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

#ifndef IOCTL_H
#define IOCTL_H

#include <ioctl_base.h>

/// IOCTL
///
/// The IOCTL class is responsible for making calls to IOCTL. This class
/// has a complicated structure designed to provide both the ability to be
/// mocked by HippoMocks, but all provide the ability to be implemented by
/// different operating systems (as there are not standard implementations
/// of an IOCTL). The structure is as follows:
///
/// @code
///
/// arch/ioctl : public ioctl_base
/// {
/// private:
///     void *d; // ioctl_private <-- actually implements IOCTL call
/// }
///
/// @endcode
///
/// With this structure, each operating system is free to implement it's
/// IOCTL as needed, while still providing the ability to be mocked up for
/// unit testing.
///
/// The IOCTL class takes a command to send, as well as the data to send and
/// the size of the data being sent. It's up to each OS specific implemetation
/// to convert the cross-platform API to an OS specific API that makes sense.
///
class ioctl : public ioctl_base
{
public:

    ioctl();
    ~ioctl();

    /// Call
    ///
    /// Makes an IOCTL call to the driver entry.
    ///
    /// @param cmd the command to send to the driver entry
    /// @param data the data to send to the driver entry
    /// @param len the length of the data to send to the driver entry
    /// @return an error code the describes the various errors that might occur
    ///
    ioctl_error::type call(ioctl_commands::type cmd,
                           const void *const data,
                           int32_t len) const override;

private:

    void *d;
};

#endif
