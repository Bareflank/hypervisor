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

#include <commit_or_rollback.h>
#include <vcpu/vcpu_intel_x64.h>

vcpu_intel_x64::vcpu_intel_x64(int64_t id) :
    vcpu(id)
{
    m_intrinsics = std::make_shared<intrinsics_intel_x64>();
    m_vmxon = std::make_shared<vmxon_intel_x64>(m_intrinsics);
    m_vmcs = std::make_shared<vmcs_intel_x64>(m_intrinsics);
    m_exit_handler = std::make_shared<exit_handler_intel_x64>(m_intrinsics);
}

vcpu_intel_x64::vcpu_intel_x64(int64_t id,
                               const std::shared_ptr<debug_ring> &debug_ring,
                               const std::shared_ptr<vmxon_intel_x64> &vmxon,
                               const std::shared_ptr<vmcs_intel_x64> &vmcs,
                               const std::shared_ptr<exit_handler_intel_x64> &exit_handler,
                               const std::shared_ptr<intrinsics_intel_x64> &intrinsics) :
    vcpu(id, debug_ring),

    m_vmxon(vmxon),
    m_vmcs(vmcs),
    m_exit_handler(exit_handler),
    m_intrinsics(intrinsics)
{
    if (!intrinsics)
        m_intrinsics = std::make_shared<intrinsics_intel_x64>();

    if (!vmxon)
        m_vmxon = std::make_shared<vmxon_intel_x64>(m_intrinsics);

    if (!vmcs)
        m_vmcs = std::make_shared<vmcs_intel_x64>(m_intrinsics);

    if (!exit_handler)
        m_exit_handler = std::make_shared<exit_handler_intel_x64>(m_intrinsics);
}

void
vcpu_intel_x64::start()
{
    auto cor1 = commit_or_rollback([&]
    { m_vmxon->stop(); });

    m_vmxon->start();

    auto host_state = vmcs_intel_x64_state(m_intrinsics);
    auto guest_state = vmcs_intel_x64_state(m_intrinsics);

    m_vmcs->launch(host_state, guest_state);

    cor1.commit();
}
