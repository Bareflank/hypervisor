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

#include <bfgsl.h>
#include <vcpu/vcpu_manager.h>

// -----------------------------------------------------------------------------
// Mutex
// -----------------------------------------------------------------------------

#include <mutex>
static std::mutex g_vcpu_manager_mutex;

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace bfvmm
{

vcpu_manager *
vcpu_manager::instance() noexcept
{
    static vcpu_manager self;
    return &self;
}

void
vcpu_manager::create_vcpu(vcpuid::type vcpuid, bfobject *obj)
{
    auto ___ = gsl::on_failure([&] {
        std::lock_guard<std::mutex> guard(g_vcpu_manager_mutex);
        m_vcpus.erase(vcpuid);
    });

    if (auto &&vcpu = add_vcpu(vcpuid, obj)) {
        vcpu->init(obj);
    }
}

void
vcpu_manager::delete_vcpu(vcpuid::type vcpuid, bfobject *obj)
{
    auto ___ = gsl::finally([&] {
        std::lock_guard<std::mutex> guard(g_vcpu_manager_mutex);
        m_vcpus.erase(vcpuid);
    });

    if (auto &&vcpu = get_vcpu(vcpuid)) {
        vcpu->fini(obj);
    }
}

void
vcpu_manager::run_vcpu(vcpuid::type vcpuid, bfobject *obj)
{
    if (auto &&vcpu = get_vcpu(vcpuid)) {
        vcpu->run(obj);
    }
}

void
vcpu_manager::hlt_vcpu(vcpuid::type vcpuid, bfobject *obj)
{
    if (auto &&vcpu = get_vcpu(vcpuid)) {
        vcpu->hlt(obj);
    }
}

vcpu_manager::vcpu_manager() noexcept :
    m_vcpu_factory(std::make_unique<vcpu_factory>())
{ }

std::unique_ptr<vcpu> &
vcpu_manager::add_vcpu(vcpuid::type vcpuid, bfobject *obj)
{
    if (auto &&vcpu = get_vcpu(vcpuid)) {
        return vcpu;
    }

    if (auto &&vcpu = m_vcpu_factory->make_vcpu(vcpuid, obj)) {
        std::lock_guard<std::mutex> guard(g_vcpu_manager_mutex);
        return m_vcpus[vcpuid] = std::move(vcpu);
    }

    throw std::runtime_error("make_vcpu returned a nullptr vcpu");
}

std::unique_ptr<vcpu> &
vcpu_manager::get_vcpu(vcpuid::type vcpuid)
{
    std::lock_guard<std::mutex> guard(g_vcpu_manager_mutex);
    return m_vcpus[vcpuid];
}

}
