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


// TODO: Get rid of the "naked new" operators. THese should be unique pointers
//     if possible (maybe shared if we have to pass them around)
//
// TODO: Change to exception logic
//
// TODO: If the launch fails, it still tries to "request" a teardown, and
// crashes with an invalid opcode.



vcpu_intel_x64::vcpu_intel_x64(int64_t id) :
    vcpu(id),
    m_vmxon(0),
    m_vmcs(0),
    m_exit_handler(0),
    m_intrinsics(0)
{
    m_intrinsics = new intrinsics_intel_x64();
    m_vmxon = new vmxon_intel_x64(m_intrinsics);
    m_vmcs = new vmcs_intel_x64(m_intrinsics);
    m_exit_handler = new exit_handler_intel_x64(m_intrinsics);
}

vcpu_intel_x64::vcpu_intel_x64(int64_t id,
                               debug_ring *debug_ring,
                               vmxon_intel_x64 *vmxon,
                               vmcs_intel_x64 *vmcs,
                               exit_handler_intel_x64 *exit_handler,
                               intrinsics_intel_x64 *intrinsics) :
    vcpu(id, debug_ring),
    m_vmxon(vmxon),
    m_vmcs(vmcs),
    m_exit_handler(exit_handler),
    m_intrinsics(intrinsics)
{
    if (intrinsics == 0)
        m_intrinsics = new intrinsics_intel_x64();

    if (vmxon == 0)
        m_vmxon = new vmxon_intel_x64(m_intrinsics);

    if (vmcs == 0)
        m_vmcs = new vmcs_intel_x64(intrinsics);

    if (exit_handler == 0)
        m_exit_handler = new exit_handler_intel_x64(m_intrinsics);
}

vcpu_error::type
vcpu_intel_x64::start()
{
    auto cor1 = commit_or_rollback([&]
    { m_vmxon->stop(); });

    m_vmxon->start();

    auto host_state = vmcs_state_intel_x64(m_intrinsics);
    auto guest_state = vmcs_state_intel_x64(m_intrinsics);

    m_vmcs->launch(host_state, guest_state);

    cor1.commit();

    return vcpu_error::success;
}

vcpu_error::type
vcpu_intel_x64::dispatch()
{
    m_exit_handler->dispatch();

    return vcpu_error::success;
}

vcpu_error::type
vcpu_intel_x64::stop()
{
    m_vmxon->stop();

    return vcpu_error::success;
}

vcpu_error::type
vcpu_intel_x64::halt()
{
    m_intrinsics->stop();

    return vcpu_error::success;
}

vcpu_error::type
vcpu_intel_x64::promote()
{
    m_vmcs->promote();

    return vcpu_error::success;
}
