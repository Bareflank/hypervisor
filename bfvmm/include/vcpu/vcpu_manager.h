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

#include <map>
#include <memory>

#include <vcpuid.h>
#include <user_data.h>
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
    /// @expects none
    /// @ensures none
    ///
    virtual ~vcpu_manager() = default;

    /// Get Singleton Instance
    ///
    /// @expects none
    /// @ensures ret != nullptr
    ///
    /// Get an instance to the singleton class.
    ///
    static vcpu_manager *instance() noexcept;

    /// Create vCPU
    ///
    /// Creates the vCPU. Note that the vCPU is actually created by the
    /// vCPU factory's make_vcpu function.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param vcpuid the vcpu to initialize
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void create_vcpu(vcpuid::type vcpuid, user_data *data = nullptr);

    /// Delete vCPU
    ///
    /// Deletes the vCPU.
    ///
    /// @param vcpuid the vcpu to stop
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void delete_vcpu(vcpuid::type vcpuid, user_data *data = nullptr);

    /// Run vCPU
    ///
    /// Executes the vCPU.
    ///
    /// @expects vcpu exists
    /// @ensures none
    ///
    /// @param vcpuid the vcpu to execute
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void run_vcpu(vcpuid::type vcpuid, user_data *data = nullptr);

    /// Halt vCPU
    ///
    /// Halts the vCPU.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param vcpuid the vcpu to halt
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void hlt_vcpu(vcpuid::type vcpuid, user_data *data = nullptr);

    /// Write to Log
    ///
    /// Write's a string the vCPU's debug ring.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param vcpuid the vCPU to write to
    /// @param str the string to write
    ///
    virtual void write(vcpuid::type vcpuid, const std::string &str) noexcept;

private:

    vcpu_manager() noexcept;
    std::unique_ptr<vcpu> &add_vcpu(vcpuid::type vcpuid, user_data *data);
    std::unique_ptr<vcpu> &get_vcpu(vcpuid::type vcpuid);

private:

    friend class vcpu_ut;

    std::map<vcpuid::type, std::unique_ptr<vcpu>> m_vcpus;

private:

    std::unique_ptr<vcpu_factory> m_vcpu_factory;

    void set_factory(std::unique_ptr<vcpu_factory> factory)
    { m_vcpu_factory = std::move(factory); }

public:

    vcpu_manager(const vcpu_manager &) = delete;
    vcpu_manager &operator=(const vcpu_manager &) = delete;
};

/// vCPU Manager Macro
///
/// The following macro can be used to quickly call the vcpu manager as
/// this class will likely be called by a lot of code. This call is guaranteed
/// to not be NULL
///
/// @expects none
/// @ensures ret != nullptr
///
#define g_vcm vcpu_manager::instance()

#endif
