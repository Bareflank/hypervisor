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

#include <gsl/gsl>

#include <vcpu/vcpu_intel_x64.h>
#include <memory_manager/memory_manager.h>

vcpu_intel_x64::vcpu_intel_x64(uint64_t id,
                               std::shared_ptr<debug_ring> debug_ring,
                               std::shared_ptr<intrinsics_intel_x64> intrinsics,
                               std::shared_ptr<vmxon_intel_x64> vmxon,
                               std::shared_ptr<vmcs_intel_x64> vmcs,
                               std::shared_ptr<exit_handler_intel_x64> exit_handler,
                               std::shared_ptr<vmcs_intel_x64_vmm_state> vmm_state,
                               std::shared_ptr<vmcs_intel_x64_vmm_state> guest_state) :
    vcpu(id, debug_ring),
    m_vmcs_launched(false),
    m_vmxon_started(false),
    m_intrinsics(std::move(intrinsics)),
    m_vmxon(std::move(vmxon)),
    m_vmcs(std::move(vmcs)),
    m_exit_handler(std::move(exit_handler)),
    m_vmm_state(std::move(vmm_state)),
    m_guest_state(std::move(guest_state))
{
}

void
vcpu_intel_x64::init(void *attr)
{
    auto fa1 = gsl::finally([&]
    { this->fini(); });

    auto ss = new state_save_intel_x64();
    m_state_save = std::shared_ptr<state_save_intel_x64>(ss);

    if (!m_intrinsics) m_intrinsics = std::make_shared<intrinsics_intel_x64>();
    if (!m_vmxon) m_vmxon = std::make_shared<vmxon_intel_x64>(m_intrinsics);
    if (!m_vmcs) m_vmcs = std::make_shared<vmcs_intel_x64>(m_intrinsics);
    if (!m_exit_handler) m_exit_handler = std::make_shared<exit_handler_intel_x64>(m_intrinsics);
    if (!m_vmm_state) m_vmm_state = std::make_shared<vmcs_intel_x64_vmm_state>(m_state_save);
    if (!m_guest_state) m_guest_state = std::make_shared<vmcs_intel_x64_host_vm_state>(m_intrinsics);

    m_state_save->vcpuid = this->id();
    m_state_save->vmxon_ptr = reinterpret_cast<uintptr_t>(m_vmxon.get());
    m_state_save->vmcs_ptr = reinterpret_cast<uintptr_t>(m_vmcs.get());
    m_state_save->exit_handler_ptr = reinterpret_cast<uintptr_t>(m_exit_handler.get());

    m_vmcs->set_state_save(m_state_save);

    m_exit_handler->set_vmcs(m_vmcs);
    m_exit_handler->set_state_save(m_state_save);

    fa1.ignore();

    vcpu::init(attr);
}

void
vcpu_intel_x64::fini(void *attr)
{
    m_guest_state.reset();
    m_vmm_state.reset();

    m_state_save.reset();

    m_exit_handler.reset();
    m_vmcs.reset();
    m_vmxon.reset();
    m_intrinsics.reset();

    vcpu::fini(attr);
}

void
vcpu_intel_x64::run(void *attr)
{
    if (!this->is_initialized())
        throw std::runtime_error("attempting to run a vcpu that has not been initialized");

    if (!m_vmcs_launched)
    {
        auto fa1 = gsl::finally([&]
        {
            if (this->is_host_vm_vcpu() && m_vmxon_started)
                m_vmxon->stop();
        });

        if (this->is_host_vm_vcpu())
        {
            m_vmxon->start();
            m_vmxon_started = true;
        }

        m_vmcs->launch(m_vmm_state, m_guest_state);
        m_vmcs_launched = true;

        fa1.ignore();
    }
    else
    {
        m_vmcs->load();
        m_vmcs->resume();
    }

    vcpu::run(attr);
}

void
vcpu_intel_x64::hlt(void *attr)
{
    if (!this->is_initialized())
        return;

    if (this->is_host_vm_vcpu() && m_vmxon_started)
    {
        m_vmxon->stop();
        m_vmxon_started = false;
    }

    m_vmcs_launched = false;
    vcpu::hlt(attr);
}
