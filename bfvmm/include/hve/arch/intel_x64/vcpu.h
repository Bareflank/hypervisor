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

#ifndef VCPU_INTEL_X64_H
#define VCPU_INTEL_X64_H

#include "exit_handler.h"
#include "vmx.h"
#include "vmcs.h"
#include "../../../vcpu/vcpu.h"

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_HVE
#ifdef SHARED_HVE
#define EXPORT_HVE EXPORT_SYM
#else
#define EXPORT_HVE IMPORT_SYM
#endif
#else
#define EXPORT_HVE
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

namespace bfvmm
{
namespace intel_x64
{

/// Intel vCPU
///
/// This class provides the base implementation for an Intel based vCPU. For
/// more information on how a vCPU works, please @see bfvmm::vcpu
///
class EXPORT_HVE vcpu : public bfvmm::vcpu
{

public:

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param id the id of the vcpu
    ///
    vcpu(vcpuid::type id) :
        bfvmm::vcpu{id}
    {
        if (this->is_host_vm_vcpu()) {
            m_vmx = std::make_unique<intel_x64::vmx>();
        }

        m_vmcs = std::make_unique<bfvmm::intel_x64::vmcs>(id);
        m_exit_handler = std::make_unique<bfvmm::intel_x64::exit_handler>(m_vmcs.get());

        this->add_run_delegate(
            run_delegate_t::create<intel_x64::vcpu, &intel_x64::vcpu::run_delegate>(this)
        );

        this->add_hlt_delegate(
            hlt_delegate_t::create<intel_x64::vcpu, &intel_x64::vcpu::hlt_delegate>(this)
        );
    }

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~vcpu() = default;

    /// Run Delegate
    ///
    /// Provides the base implementation for starting the vCPU. This delegate
    /// does not "resume" a vCPU as the base implementation does not support
    /// guest VMs.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param obj ignored
    ///
    void run_delegate(bfobject *obj)
    {
        bfignored(obj);

        m_vmcs->load();
        m_vmcs->launch();

        ::x64::cpuid::get(0xBF10, 0, 0, 0);

        if (this->is_host_vm_vcpu()) {
            ::x64::cpuid::get(0xBF11, 0, 0, 0);
        }
    }

    /// Halt Delegate
    ///
    /// Provides the base implementation for stopping the vCPU.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param obj ignored
    ///
    void hlt_delegate(bfobject *obj)
    {
        bfignored(obj);

        ::x64::cpuid::get(0xBF20, 0, 0, 0);

        if (this->is_host_vm_vcpu()) {
            ::x64::cpuid::get(0xBF21, 0, 0, 0);
        }
    }

    /// Get VMCS
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return Returns a pointer to the vCPU's VMCS
    ///
    bfvmm::intel_x64::vmcs *vmcs()
    { return m_vmcs.get(); }

    /// Get Exit Handler
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return Returns a pointer to the vCPU's exit handler
    ///
    bfvmm::intel_x64::exit_handler *exit_handler()
    { return m_exit_handler.get(); }

private:

    std::unique_ptr<bfvmm::intel_x64::exit_handler> m_exit_handler;
    std::unique_ptr<bfvmm::intel_x64::vmcs> m_vmcs;
    std::unique_ptr<bfvmm::intel_x64::vmx> m_vmx;
};

}
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
