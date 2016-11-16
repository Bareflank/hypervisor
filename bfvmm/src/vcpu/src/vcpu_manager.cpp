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

#include <debug.h>
#include <vcpu/vcpu_manager.h>

// -----------------------------------------------------------------------------
// Mutex
// -----------------------------------------------------------------------------

#include <mutex>
std::mutex g_vcpu_manager_mutex;

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

vcpu_manager *
vcpu_manager::instance() noexcept
{
    static vcpu_manager self;
    return &self;
}

void
vcpu_manager::create_vcpu(uint64_t vcpuid, void *attr)
{
    auto ___ = gsl::on_failure([&]
    {
        std::lock_guard<std::mutex> guard(g_vcpu_manager_mutex);
        m_vcpus.erase(vcpuid);
    });

    if (auto && vcpu = add_vcpu(vcpuid, attr))
        vcpu->init(attr);
}

void
vcpu_manager::delete_vcpu(uint64_t vcpuid, void *attr)
{
    auto ___ = gsl::finally([&]
    {
        std::lock_guard<std::mutex> guard(g_vcpu_manager_mutex);
        m_vcpus.erase(vcpuid);
    });

    if (auto && vcpu = get_vcpu(vcpuid))
        vcpu->fini(attr);
}

void
vcpu_manager::run_vcpu(uint64_t vcpuid, void *attr)
{
    if (auto && vcpu = get_vcpu(vcpuid))
    {
        if (!vcpu->is_running())
            vcpu->run(attr);
        else
            throw std::logic_error("vcpu is already running");

        if (vcpu->is_guest_vm_vcpu())
            return;

        bfdebug << "success: host os is " << bfcolor_green "now " << bfcolor_end
                << "in a vm on vcpuid = " << vcpuid << bfendl;
    }
    else
    {
        throw std::invalid_argument("invalid vcpuid");
    }
}

void
vcpu_manager::hlt_vcpu(uint64_t vcpuid, void *attr)
{
    if (auto && vcpu = get_vcpu(vcpuid))
    {
        if (vcpu->is_running())
            vcpu->hlt(attr);
        else
            return;

        if (vcpu->is_guest_vm_vcpu())
            return;

        bfdebug << "success: host os is " << bfcolor_red "not " << bfcolor_end
                << "in a vm on vcpuid = " << vcpuid << bfendl;
    }
}

void
vcpu_manager::write(uint64_t vcpuid, const std::string &str) noexcept
{
    if (auto && vcpu = get_vcpu(vcpuid))
        vcpu->write(str);
}

vcpu_manager::vcpu_manager() noexcept :
    m_vcpu_factory(std::make_unique<vcpu_factory>())
{ }

std::unique_ptr<vcpu> &
vcpu_manager::add_vcpu(uint64_t vcpuid, void *attr)
{
    if (!m_vcpu_factory)
        throw std::runtime_error("invalid vcpu factory");

    if (auto && vcpu = get_vcpu(vcpuid))
        return vcpu;

    if (auto && vcpu = m_vcpu_factory->make_vcpu(vcpuid, attr))
    {
        std::lock_guard<std::mutex> guard(g_vcpu_manager_mutex);
        return m_vcpus[vcpuid] = std::move(vcpu);
    }

    throw std::runtime_error("make_vcpu returned a nullptr vcpu");
}

std::unique_ptr<vcpu> &
vcpu_manager::get_vcpu(uint64_t vcpuid)
{
    std::lock_guard<std::mutex> guard(g_vcpu_manager_mutex);
    return m_vcpus[vcpuid];
}
