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

#ifndef VCPU_FACTORY_H
#define VCPU_FACTORY_H

#include <memory>
#include "vcpu.h"

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

/// vCPU Factory
///
/// This class is used by the vcpu_manager to create vCPUs. Specifically,
/// this class provides a seem that allows users of Bareflank to replace the
/// default vCPU with their own, custom vCPUs that extend the functionality
/// of Bareflank above and beyond what is already provided. This seems also
/// provides a means to unit test the vcpu_manager.
///
/// To provide custom logic, define your own make_vcpu function, in your
/// own vcpu_factory module, and load your module instead of the module that
/// is provided by Bareflank. For an example of how to do this, please
/// see:
///
/// <a href="https://github.com/Bareflank/hypervisor_example_vpid">Bareflank Hypervisor VPID Example</a>
/// <br>
/// <a href="https://github.com/Bareflank/hypervisor_example_cpuidcount">Bareflank Hypervisor CPUID Example</a>
///
class EXPORT_VCPU vcpu_factory
{
public:

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    vcpu_factory() noexcept = default;

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual ~vcpu_factory() = default;

    /// Make vCPU
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param vcpuid the vcpuid for the vcpu to create
    /// @param obj object passed to the vcpu
    /// @return returns a pointer to a newly created vCPU.
    ///
    virtual std::unique_ptr<vcpu> make(
        vcpuid::type vcpuid, bfobject *obj = nullptr);

public:

    /// @cond

    vcpu_factory(vcpu_factory &&) noexcept = default;
    vcpu_factory &operator=(vcpu_factory &&) noexcept = default;

    vcpu_factory(const vcpu_factory &) = delete;
    vcpu_factory &operator=(const vcpu_factory &) = delete;

    /// @endcond
};

}

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
