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

#include <debug.h>
#include <exception.h>
#include <vcpu/vcpu_manager.h>

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

#define vcpu_execute(a,b) \
    if (a < 0 || a >= MAX_VCPUS) \
        throw std::out_of_range("vcpu id is out of range"); \
    \
    std::lock_guard<std::mutex> guard(g_vcpu_manager_mutex); \
    auto &vc = m_vcpus[a]; \
    g_vcpu_manager_mutex.unlock(); \
    \
    if (!vc) \
        throw std::out_of_range("vcpu not yet initialized"); \
    \
    vc->b();

// -----------------------------------------------------------------------------
// Mutex
// -----------------------------------------------------------------------------

#include <mutex>
std::mutex g_vcpu_manager_mutex;

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

vcpu_manager *
vcpu_manager::instance()
{
    static vcpu_manager self;
    return &self;
}

void
vcpu_manager::init(int64_t vcpuid)
{
    if (vcpuid < 0 || vcpuid >= MAX_VCPUS)
        throw std::out_of_range("vcpu id");

    auto vcpu = m_vcpu_factory->make_vcpu(vcpuid);

    std::lock_guard<std::mutex> guard(g_vcpu_manager_mutex);
    m_vcpus[vcpuid] = vcpu;
}

void
vcpu_manager::start(int64_t vcpuid)
{
    vcpu_execute(vcpuid, start);

    bfdebug << "success: host os is " << bfcolor_green "now " << bfcolor_end
            << "in a vm on vcpuid = " << vcpuid << bfendl;
}

void
vcpu_manager::stop(int64_t vcpuid)
{
    vcpu_execute(vcpuid, stop);

    bfdebug << "success: host os is " << bfcolor_red "not " << bfcolor_end
            << "in a vm on vcpuid = " << vcpuid << bfendl;

    vc.reset();
}

void
vcpu_manager::write(int64_t vcpuid, const std::string &str)
{
    if (vcpuid < 0 || vcpuid >= MAX_VCPUS)
        vcpuid = 0;

    std::lock_guard<std::mutex> guard(g_vcpu_manager_mutex);
    const auto &vc = m_vcpus[vcpuid];
    g_vcpu_manager_mutex.unlock();

    if (!vc)
        return;

    vc->write(str);
}

vcpu_manager::vcpu_manager() :
    m_vcpus(MAX_VCPUS),
    m_vcpu_factory(std::make_shared<vcpu_factory>())
{
}
