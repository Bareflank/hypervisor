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

#include "../../vcpu_factory.h"

#include "../../../hve/arch/intel_x64/vmx/vmx.h"
#include "../../../hve/arch/intel_x64/vmcs/vmcs.h"
#include "../../../hve/arch/intel_x64/exit_handler/exit_handler.h"

namespace bfvmm
{
namespace intel_x64
{

/// Intel vCPU
///
/// This class provides the base implementation for an Intel based vCPU. For
/// more information on how a vCPU works, please @see bfvmm::vcpu
///
class vcpu : public bfvmm::vcpu
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
    }

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~vcpu() override
    {
        if (this->is_host_vm_vcpu()) {
            m_vmx.reset();
        }

        m_vmcs.reset();
        m_exit_handler.reset();
    }

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
    }

    /// Get VMCS
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return Returns a pointer to the vCPU's VMCS
    ///
    auto vmcs() const noexcept
    { return m_vmcs.get(); }

    /// Get Exit Handler
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return Returns a pointer to the vCPU's exit handler
    ///
    auto exit_handler() const noexcept
    { return m_exit_handler.get(); }

private:

    std::unique_ptr<bfvmm::intel_x64::vmx> m_vmx;
    std::unique_ptr<bfvmm::intel_x64::vmcs> m_vmcs;
    std::unique_ptr<bfvmm::intel_x64::exit_handler> m_exit_handler;
};

}
}
