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

#ifndef VCPU_MANAGER_H
#define VCPU_MANAGER_H

#include <map>
#include <memory>

#include "vcpu_factory.h"

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_VCPU
#ifdef SHARED_VCPU
#define EXPORT_VCPU EXPORT_SYM
#else
#define EXPORT_VCPU IMPORT_SYM
#endif
#else
#define EXPORT_VCPU
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm
{

/// vCPU Manager
///
/// The vCPU manager is responsible for creating / destroying vCPUs, and
/// calling a vCPU's interface, depending on which vcpuid is provided. If you
/// need to work with a vCPU, but all you have is a vcpuid, this is the class
/// to use.
///
class EXPORT_VCPU vcpu_manager
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
    /// @return a singleton instance of vcpu_manager
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
    /// @param obj object that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void create_vcpu(
        vcpuid::type vcpuid, bfobject *obj = nullptr);

    /// Delete vCPU
    ///
    /// Deletes the vCPU.
    ///
    /// @param vcpuid the vcpu to stop
    /// @param obj object that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void delete_vcpu(
        vcpuid::type vcpuid, bfobject *obj = nullptr);

    /// Run vCPU
    ///
    /// Executes the vCPU.
    ///
    /// @expects vcpu exists
    /// @ensures none
    ///
    /// @param vcpuid the vcpu to execute
    /// @param obj object that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void run_vcpu(
        vcpuid::type vcpuid, bfobject *obj = nullptr);

    /// Halt vCPU
    ///
    /// Halts the vCPU.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param vcpuid the vcpu to halt
    /// @param obj object that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void hlt_vcpu(
        vcpuid::type vcpuid, bfobject *obj = nullptr);

    /// Set Factory
    ///
    /// Should only be used by unit tests
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param factory the new factory to use
    ///
    void set_factory(std::unique_ptr<vcpu_factory> factory)
    { m_vcpu_factory = std::move(factory); }

private:

    vcpu_manager() noexcept;
    std::unique_ptr<vcpu> &add_vcpu(vcpuid::type vcpuid, bfobject *obj);
    std::unique_ptr<vcpu> &get_vcpu(vcpuid::type vcpuid);

private:

    std::unique_ptr<vcpu_factory> m_vcpu_factory;
    std::map<vcpuid::type, std::unique_ptr<vcpu>> m_vcpus;

public:

    /// @cond

    vcpu_manager(vcpu_manager &&) noexcept = delete;
    vcpu_manager &operator=(vcpu_manager &&) noexcept = delete;

    vcpu_manager(const vcpu_manager &) = delete;
    vcpu_manager &operator=(const vcpu_manager &) = delete;

    /// @endcond
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
#define g_vcm bfvmm::vcpu_manager::instance()

}

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
