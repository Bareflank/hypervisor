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

#ifndef DEBUG_RING_H
#define DEBUG_RING_H

#include <string>
#include <memory>

#include <stdint.h>
#include <debug_ring_interface.h>

/// Debug Ring
///
/// The debug ring is a simple debug facility that allows the vmm to write
/// string data into a ring buffer while a reader that has shared access to
/// the same buffer can read from the debug ring to extract the strings
/// that are written to the buffer.
///
class debug_ring
{
public:

    /// Default Constructor
    ///
    debug_ring(uint64_t vcpuid) noexcept;

    /// Debug Ring Destructor
    ///
    virtual ~debug_ring() noexcept;

    /// Write to Debug Ring
    ///
    /// Writes a string to the debug ring. If the string is larger than
    /// the debug ring's internal buffer, the write will fail. If the debug
    /// ring is full, the write will keep removing existing strings in the
    /// buffer until enough space is made, to add the string.
    ///
    /// @param str the string to write to the debug ring
    ///
    /// @throws invalid_debug_ring thrown if the debug_ring that was
    ///     constructed is invalid (likely due to an invalid vcpuid)
    /// @throws range_error thrown if the string that is provided is too large
    ///
    virtual void write(const std::string &str) noexcept;

private:

    uint64_t m_vcpuid;
    std::unique_ptr<debug_ring_resources_t> m_drr;
};

/// Get Debug Ring Resource
///
/// Returns a pointer to a debug_ring_resources_t for a given CPU.
///
/// @param vcpuid defines which debug ring to return
/// @param drr the resulting debug ring
/// @return the debug_ring_resources_t for the provided vcpuid
///
extern "C" int64_t get_drr(uint64_t vcpuid, struct debug_ring_resources_t **drr) noexcept;

#endif
