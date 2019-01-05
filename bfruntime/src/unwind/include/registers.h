//
// Bareflank Unwind Library
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

#ifndef REGISTERS_H
#define REGISTERS_H

#include <stdint.h>

#define MAX_NUM_REGISTERS 32

/// Register State
///
/// Defines the state of the registers. When the unwinder first starts, it will
/// get the state of the registers as its first operation. From that point
/// it will locate the FDE associated with the instruction pointer, and unwind
/// the stack. The process of unwinding the stack is to change the register
/// state stored here, which at a minimum changes the instruction pointer and
/// the stack register (but likely also changes other registers). From there
/// the next FDE is located, and the process repeats until the personality
/// function says when to stop
///
/// Once the "catch" block is found, the register state can be used to resume
/// into a new CFA by loading the register state.
///
class register_state
{
public:

    /// Default Constructor
    ///
    register_state() = default;

    /// Destructor
    ///
    virtual ~register_state() = default;

    /// Default Move Constructor
    ///
    register_state(register_state &&) noexcept = default;

    /// Default Copy Constructor
    ///
    register_state(const register_state &) = default;

    /// Default Move Assignment Operator
    ///
    register_state &operator=(register_state &&) noexcept = default;

    /// Default Copy Assignment Operator
    ///
    register_state &operator=(const register_state &) = default;

    /// Get Instruction Pointer
    ///
    /// @return returns the instruction pointer value
    ///
    virtual uint64_t get_ip() const
    { return 0; }

    /// Set Instruction Pointer
    ///
    /// Note: the write is staged and must be committed using the commit
    /// function
    ///
    /// @param value the value to set the instruction pointer to
    /// @return returns this register state for chaining
    ///
    virtual register_state &set_ip(uint64_t value)
    { (void) value; return *this; }

    /// Get General Purpose Register
    ///
    /// @param index the general purpose register to get
    /// @return returns the value of the general purpose register requested
    ///
    virtual uint64_t get(uint64_t index) const
    { (void) index; return 0; }

    /// Set General Purpose Register
    ///
    /// Note: the write is staged and must be committed using the commit
    /// function
    ///
    /// @param index the general purpose register to set
    /// @param value the value to set the general purpose register to
    /// @return returns this register state for chaining
    ///
    virtual register_state &set(uint64_t index, uint64_t value)
    { (void) index; (void) value; return *this; }

    /// Commit
    ///
    /// Commits any pending changes to the register state
    ///
    virtual void commit()
    { }

    /// Commit with CFA
    ///
    /// Commits any pending changes to the register state, and saves the
    /// provided cfa in the stack register
    ///
    /// @param cfa the canonical frame address to save to the stack register
    ///
    virtual void commit(uint64_t cfa)
    { (void) cfa; }

    /// Resume
    ///
    /// Restores the register state. Note that this function does not return.
    ///
    virtual void resume()
    { }

    /// Max Number of Registers
    ///
    /// @return returns the maximum number of registers that this register
    /// state stores. This is usually defined by the associated ABI
    ///
    virtual uint64_t max_num_registers() const
    { return 0; }

    /// Register Name
    ///
    /// @param index the index of the register to get the name for
    /// @return returns the name of the register requested
    ///
    virtual const char *name(uint64_t index) const
    { (void) index; return "forgot to overload name"; }

    /// Dump
    ///
    /// Prints the value of each register. Make sure that logging is enabled
    /// before using this function
    ///
    virtual void dump() const
    { }
};

#endif
