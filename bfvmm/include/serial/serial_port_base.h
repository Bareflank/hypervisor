//
// Bareflank Hypervisor
// Copyright (C) 2017 Assured Information Security, Inc.
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

#ifndef SERIAL_PORT_BASE_H
#define SERIAL_PORT_BASE_H

#include <cstdint>

#include <intrinsics/common.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_SERIAL
#ifdef SHARED_SERIAL
#define EXPORT_SERIAL EXPORT_SYM
#else
#define EXPORT_SERIAL IMPORT_SYM
#endif
#else
#define EXPORT_SERIAL
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

/// Serial port base class
///
/// This class provides an interface to the basic functions of a serial port,
/// and also provides abstracted IO functions to its subclasses.
///
class EXPORT_SERIAL serial_port_base
{
public:
#if defined(BF_X64)
    using port_type = x64::portio::port_addr_type;
    using value_type_8 = x64::portio::port_8bit_type;
    using value_type_32 = x64::portio::port_32bit_type;
#elif defined(BF_AARCH64)
    using port_type = uintptr_t;
    using value_type_8 = uint8_t;
    using value_type_32 = uint32_t;
#else
#   error "No serial port implementation for this architecture"
#endif

public:
    virtual ~serial_port_base() = default;

    /// Port
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return the serial device's port
    virtual port_type port() const noexcept = 0;

    /// Set Port
    ///
    /// Change the peripheral port/base address at runtime.
    ///
    /// @param port serial peripheral port or base address
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual void set_port(port_type port) noexcept = 0;

    /// Write Character
    ///
    /// Writes a character to the serial device.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param c character to write
    ///
    virtual void write(char c) noexcept = 0;

    /// Write String
    ///
    /// Writes a string to the serial device.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param str string to write
    ///
    virtual void write(const std::string &str) noexcept;

    /// Write String
    ///
    /// Writes a string to the serial device.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param str string to write
    /// @param len length of the string to write
    ///
    virtual void write(const char *str, size_t len) noexcept;

protected:

    /// Read 8 bits from IO
    ///
    /// Reads a value from IO. Implementation is architecture-dependent
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param offset offset (in bytes) from the base address returned by port()
    /// @return data loaded from the offset given
    ///
    value_type_8 offset_inb(port_type offset) const noexcept;

    /// Read 32 bits from IO
    ///
    /// Reads a value from IO. Implementation is architecture-dependent
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param offset offset (in bytes) from the base address returned by port()
    /// @return data loaded from the offset given
    ///
    value_type_32 offset_ind(port_type offset) const noexcept;

    /// Write 8 bits to IO
    ///
    /// Writes a value to IO. Implementation is architecture-dependent
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param offset offset (in bytes) from the base address returned by port()
    /// @param data value to write to the offset given
    ///
    void offset_outb(port_type offset, value_type_8 data) const noexcept;

    /// Write 32 bits to IO
    ///
    /// Writes a value to IO. Implementation is architecture-dependent
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param offset offset (in bytes) from the base address returned by port()
    /// @param data value to write to the offset given
    ///
    void offset_outd(port_type offset, value_type_32 data) const noexcept;
};

#endif
