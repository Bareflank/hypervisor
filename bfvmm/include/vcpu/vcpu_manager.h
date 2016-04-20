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

#ifndef VCPU_MANAGER_H
#define VCPU_MANAGER_H

#include <vector>
#include <memory>
#include <vcpu/vcpu_factory.h>

/// vCPU Manager
///
/// The vCPU manager is responsible for creating / destroying vCPUs, and
/// calling a vCPU's interface, depending on which vcpuid is provided. If you
/// need to work with a vCPU, but all you have is a vcpuid, this is the class
/// to use.
///
class vcpu_manager
{
public:

    /// Destructor
    ///
    ~vcpu_manager() {}

    /// Get Singleton Instance
    ///
    /// Get an instance to the singleton class.
    ///
    static vcpu_manager *instance();

    /// Init vCPU
    ///
    /// Initializes the vCPU.
    ///
    /// @param vcpuid the vcpu to initialize
    /// @throws invalid_argument_error thrown when the vcpuid is invalid
    ///
    virtual void init(int64_t vcpuid);

    /// Start vCPU
    ///
    /// Starts the vCPU.
    ///
    /// @param vcpuid the vcpu to start
    /// @throws invalid_argument_error thrown when the vcpuid is invalid, or
    ///     if the vcpuid has yet to be initialized
    ///
    virtual void start(int64_t vcpuid);

    /// Dispatch vCPU exit handler
    ///
    /// Runs the vCPU's exit handler
    ///
    /// @param vcpuid the vcpu to stop
    /// @throws invalid_argument_error thrown when the vcpuid is invalid, or
    ///     if the vcpuid has yet to be initialized
    ///
    virtual void dispatch(int64_t vcpuid);

    /// Stop vCPU
    ///
    /// Stops the vCPU.
    ///
    /// @param vcpuid the vcpu to stop
    /// @throws invalid_argument_error thrown when the vcpuid is invalid, or
    ///     if the vcpuid has yet to be initialized
    ///
    virtual void stop(int64_t vcpuid);

    /// Halt vCPU
    ///
    /// Halts the vCPU.
    ///
    /// @param vcpuid the vcpu to halt
    /// @throws invalid_argument_error thrown when the vcpuid is invalid, or
    ///     if the vcpuid has yet to be initialized
    ///
    virtual void halt(int64_t vcpuid);

    /// Promote vCPU
    ///
    /// Promote vCPU to host CPU state
    ///
    /// @param vcpuid the vcpu to promote
    /// @throws invalid_argument_error thrown when the vcpuid is invalid, or
    ///     if the vcpuid has yet to be initialized
    ///
    virtual void promote(int64_t vcpuid);

    /// Write to Log
    ///
    /// Writes a string 'str' of length 'len' to a vcpuid's internal debug
    /// ring. If the vcpuid provided is invalid, all of the string is written
    /// to all of the vcpus
    ///
    /// @param vcpuid the vcpu's log to write to
    /// @param str the string to write to the log
    ///
    virtual void write(int64_t vcpuid, const std::string &str);

public:

    /// Disable the copy consturctor
    ///
    vcpu_manager(const vcpu_manager &) = delete;

    /// Disable the copy operator
    ///
    vcpu_manager &operator=(const vcpu_manager &) = delete;

private:

    /// Default Constructor
    ///
    vcpu_manager();

private:

    std::vector<std::shared_ptr<vcpu> > m_vcpus;

private:

    friend class vcpu_ut;

    /// The vCPU factory is a seem that provides better access for unit
    /// testing, which allows us to create misbehaving vcpus
    ///
    std::shared_ptr<vcpu_factory> m_vcpu_factory;

    /// Set vCPU Factory
    ///
    void set_factory(const std::shared_ptr<vcpu_factory> &factory)
    { m_vcpu_factory = factory; }
};

/// vCPU Manager Macro
///
/// The following macro can be used to quickly call the vcpu manager as
/// this class will likely be called by a lot of code. This call is guaranteed
/// to not be NULL
///
#define g_vcm vcpu_manager::instance()

#endif
