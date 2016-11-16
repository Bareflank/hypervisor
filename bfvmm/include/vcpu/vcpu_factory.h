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

#ifndef VCPU_FACTORY_H
#define VCPU_FACTORY_H

#include <memory>
#include <vcpu/vcpu.h>

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
class vcpu_factory
{
public:

    /// Default Constructor
    ///
    vcpu_factory() noexcept = default;

    /// Destructor
    ///
    virtual ~vcpu_factory() = default;

    /// Make vCPU
    ///
    /// @param vcpuid the vcpuid for the vcpu to create
    /// @param attr attributes used to determine which type of vcpu to create
    /// @return returns a pointer to a newly created vCPU.
    ///
    virtual std::unique_ptr<vcpu> make_vcpu(uint64_t vcpuid, void *attr = nullptr);
};

#endif
