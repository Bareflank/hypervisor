//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
// Author: Connor Davis      <davisc@ainfosec.com>
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

#ifndef VMCS_INTEL_X64_HELPERS_H
#define VMCS_INTEL_X64_HELPERS_H

#include <type_traits>
#include <intrinsics/vmx_intel_x64.h>
#include <intrinsics/msrs_intel_x64.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace vmcs
{

using field_type = uint64_t;
using value_type = uint64_t;

template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
auto get_vmcs_field(T addr, const char *name, bool exists)
{
    if (!exists)
        throw std::logic_error("get_vmcs_field failed: "_s + name + " field doesn't exist");

    return intel_x64::vm::read(addr, name);
}

template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
auto get_vmcs_field_if_exists(T addr, const char *name, bool verbose, bool exists)
{
    if (exists)
        return intel_x64::vm::read(addr, name);

    if (!exists && verbose)
        bfwarning << "get_vmcs_field_if_exists failed: " << name << " field doesn't exist" << bfendl;

    return 0UL;
}

template <class V, class A,
          class = typename std::enable_if<std::is_integral<V>::value>::type,
          class = typename std::enable_if<std::is_integral<A>::value>::type>
auto set_vmcs_field(V val, A addr, const char *name, bool exists)
{
    if (!exists)
        throw std::logic_error("set_vmcs_field failed: "_s + name + " field doesn't exist");

    intel_x64::vm::write(addr, val, name);
}

template <class V, class A,
          class = typename std::enable_if<std::is_integral<V>::value>::type,
          class = typename std::enable_if<std::is_integral<A>::value>::type>
auto set_vmcs_field_if_exists(V val, A addr, const char *name, bool verbose, bool exists) noexcept
{
    if (exists)
        intel_x64::vm::write(addr, val, name);

    if (!exists && verbose)
        bfwarning << "set_vmcs_field failed: " << name << " field doesn't exist" << bfendl;
}

template <class MA, class CA, class M,
          class = typename std::enable_if<std::is_integral<MA>::value>::type,
          class = typename std::enable_if<std::is_integral<CA>::value>::type,
          class = typename std::enable_if<std::is_integral<M>::value>::type>
auto set_vm_control(bool val, MA msr_addr, CA ctls_addr, const char *name, M mask, bool field_exists)
{
    if (!field_exists)
        throw std::logic_error("set_vm_control failed: "_s + name + " control doesn't exist");

    if (!val)
    {
        auto is_allowed0 = (intel_x64::msrs::get(msr_addr) & mask) == 0;

        if (!is_allowed0)
            throw std::logic_error("set_vm_control failed: "_s + name + " control is not allowed to be cleared to 0");

        intel_x64::vm::write(ctls_addr, (intel_x64::vm::read(ctls_addr, name) & ~mask), name);
    }
    else
    {
        auto is_allowed1 = (intel_x64::msrs::get(msr_addr) & (mask << 32)) != 0;

        if (!is_allowed1)
            throw std::logic_error("set_vm_control failed: "_s + name + " control is not allowed to be set to 1");

        intel_x64::vm::write(ctls_addr, (intel_x64::vm::read(ctls_addr, name) | mask), name);
    }
}

template <class MA, class CA, class M,
          class = typename std::enable_if<std::is_integral<MA>::value>::type,
          class = typename std::enable_if<std::is_integral<CA>::value>::type,
          class = typename std::enable_if<std::is_integral<M>::value>::type>
auto set_vm_control_if_allowed(bool val, MA msr_addr, CA ctls_addr, const char *name,
                               M mask, bool verbose, bool field_exists) noexcept
{
    if (!field_exists)
    {
        bfwarning << "set_vm_control_if_allowed failed: " << name << " control doesn't exist" << bfendl;
        return;
    }

    if (!val)
    {
        auto is_allowed0 = (intel_x64::msrs::get(msr_addr) & mask) == 0;

        if (is_allowed0)
        {
            intel_x64::vm::write(ctls_addr, (intel_x64::vm::read(ctls_addr, name) & ~mask), name);
        }
        else
        {
            if (verbose)
            {
                bfwarning << "set_vm_control_if_allowed failed: " << name
                          << "control is not allowed to be cleared to 0" << bfendl;
            }
        }
    }
    else
    {
        auto is_allowed1 = (intel_x64::msrs::get(msr_addr) & (mask << 32)) != 0;

        if (is_allowed1)
        {
            intel_x64::vm::write(ctls_addr, (intel_x64::vm::read(ctls_addr, name) | mask), name);
        }
        else
        {
            if (verbose)
            {
                bfwarning << "set_vm_control_if_allowed failed: " << name
                          << "control is not allowed to be set to 1" << bfendl;
            }
        }
    }
}

}
}

// *INDENT-ON*

#endif
