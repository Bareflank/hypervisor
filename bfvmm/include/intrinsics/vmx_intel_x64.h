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

#ifndef VMX_INTEL_X64_H
#define VMX_INTEL_X64_H

#include <gsl/gsl>
#include <debug.h>

extern "C" bool __vmxon(void *ptr) noexcept;
extern "C" bool __vmxoff(void) noexcept;
extern "C" bool __vmclear(void *ptr) noexcept;
extern "C" bool __vmptrld(void *ptr) noexcept;
extern "C" bool __vmptrst(void *ptr) noexcept;
extern "C" bool __vmread(uint64_t field, uint64_t *val) noexcept;
extern "C" bool __vmwrite(uint64_t field, uint64_t val) noexcept;
extern "C" bool __vmlaunch_demote(void) noexcept;
extern "C" bool __invept(uint64_t type, void *ptr) noexcept;
extern "C" bool __invvpid(uint64_t type, void *ptr) noexcept;

// *INDENT-OFF*

namespace intel_x64
{
namespace vmx
{
    using vpid_type = uint64_t;
    using eptp_type = uint64_t;
    using integer_pointer = uintptr_t;

    inline void on(gsl::not_null<void *> ptr)
    {
        if (!__vmxon(ptr))
            throw std::runtime_error("vmx::on failed");
    }

    inline void off()
    {
        if (!__vmxoff())
            throw std::runtime_error("vmx::off failed");
    }

    inline void invept_single_context(eptp_type eptp)
    {
        uint64_t descriptor[2] = { eptp, 0 };
        if (!__invept(1, static_cast<void *>(descriptor)))
            throw std::runtime_error("vm::invept_singal_context failed");
    }

    inline void invept_global()
    {
        uint64_t descriptor[2] = { 0, 0 };
        if (!__invept(2, static_cast<void *>(descriptor)))
            throw std::runtime_error("vm::invept_global failed");
    }

    inline void invvpid_individual_address(vpid_type vpid, integer_pointer addr)
    {
        uint64_t descriptor[2] = { vpid, addr };
        if (!__invvpid(0, static_cast<void *>(descriptor)))
            throw std::runtime_error("vm::invvpid_individual_address failed");
    }

    inline void invvpid_single_context(vpid_type vpid)
    {
        uint64_t descriptor[2] = { vpid, 0 };
        if (!__invvpid(1, static_cast<void *>(descriptor)))
            throw std::runtime_error("vm::invvpid_single_context failed");
    }

    inline void invvpid_all_contexts()
    {
        uint64_t descriptor[2] = { 0, 0 };
        if (!__invvpid(2, static_cast<void *>(descriptor)))
            throw std::runtime_error("vm::invvpid_all_contexts failed");
    }

    inline void invvpid_single_context_global(vpid_type vpid)
    {
        uint64_t descriptor[2] = { vpid, 0 };
        if (!__invvpid(3, static_cast<void *>(descriptor)))
            throw std::runtime_error("vm::invvpid_single_context_global failed");
    }
}

namespace vm
{
    using field_type = uint64_t;
    using value_type = uint64_t;
    using name_type = const char *;
    using integer_pointer = uintptr_t;

    inline void clear(gsl::not_null<void *> ptr)
    {
        if (!__vmclear(ptr))
            throw std::runtime_error("vm::clear failed");
    }

    inline void load(gsl::not_null<void *> ptr)
    {
        if (!__vmptrld(ptr))
            throw std::runtime_error("vm::load failed");
    }

    inline void reset(gsl::not_null<void *> ptr)
    {
        if (!__vmptrst(ptr))
            throw std::runtime_error("vm::reset failed");
    }

    inline auto read(field_type field, name_type name = "")
    {
        value_type value;

        if (!__vmread(field, &value))
        {
            bferror << "vm::read failed:" << bfendl;
            bferror << "    - field: " << name << bfendl;

            throw std::runtime_error("vm::read failed");
        }

        return value;
    }

    inline void write(field_type field, value_type value, name_type name = "")
    {
        if (!__vmwrite(field, value))
        {
            bferror << "vm::write failed:" << bfendl;
            bferror << "    - field: " << name << bfendl;
            bferror << "    - value: " << view_as_pointer(value) << bfendl;

            throw std::runtime_error("vm::write failed");
        }
    }

    inline void launch_demote()
    {
        if (!__vmlaunch_demote())
            throw std::runtime_error("vm::launch_demote failed");
    }
}
}

// *INDENT-ON*

#endif
