//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef VMX_INTEL_X64_H
#define VMX_INTEL_X64_H

#include <bfgsl.h>
#include <bfdebug.h>
#include <bfbitmanip.h>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

extern "C" bool _vmxon(void *ptr) noexcept;
extern "C" bool _vmxoff(void) noexcept;
extern "C" bool _vmclear(void *ptr) noexcept;
extern "C" bool _vmptrld(void *ptr) noexcept;
extern "C" bool _vmptrst(void *ptr) noexcept;
extern "C" bool _vmread(uint64_t field, uint64_t *value) noexcept;
extern "C" bool _vmwrite(uint64_t field, uint64_t value) noexcept;
extern "C" bool _vmlaunch_demote(void) noexcept;
extern "C" bool _invept(uint64_t type, void *ptr) noexcept;
extern "C" bool _invvpid(uint64_t type, void *ptr) noexcept;
extern "C" uintptr_t _vmcall(uintptr_t r1, uintptr_t r2, uintptr_t r3, uintptr_t r4) noexcept;
extern "C" uintptr_t _vmcall1(void *r1) noexcept;
extern "C" uintptr_t _vmcall2(void *r1, void *r2) noexcept;
extern "C" uintptr_t _vmcall3(void *r1, void *r2, void *r3) noexcept;
extern "C" uintptr_t _vmcall4(void *r1, void *r2, void *r3, void *r4) noexcept;

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
        if (!_vmxon(ptr)) {
            throw std::runtime_error("vmx::on failed");
        }
    }

    inline void off()
    {
        if (!_vmxoff()) {
            throw std::runtime_error("vmx::off failed");
        }
    }

    inline void invept_single_context(eptp_type eptp)
    {
        uint64_t descriptor[2] = { eptp, 0 };
        if (!_invept(1, static_cast<void *>(descriptor))) {
            throw std::runtime_error("vm::invept_singal_context failed");
        }
    }

    inline void invept_global()
    {
        uint64_t descriptor[2] = { 0, 0 };
        if (!_invept(2, static_cast<void *>(descriptor))) {
            throw std::runtime_error("vm::invept_global failed");
        }
    }

    inline void invvpid_individual_address(vpid_type vpid, integer_pointer addr)
    {
        uint64_t descriptor[2] = { vpid, addr };
        if (!_invvpid(0, static_cast<void *>(descriptor))) {
            throw std::runtime_error("vm::invvpid_individual_address failed");
        }
    }

    inline void invvpid_single_context(vpid_type vpid)
    {
        uint64_t descriptor[2] = { vpid, 0 };
        if (!_invvpid(1, static_cast<void *>(descriptor))) {
            throw std::runtime_error("vm::invvpid_single_context failed");
        }
    }

    inline void invvpid_all_contexts()
    {
        uint64_t descriptor[2] = { 0, 0 };
        if (!_invvpid(2, static_cast<void *>(descriptor))) {
            throw std::runtime_error("vm::invvpid_all_contexts failed");
        }
    }

    inline void invvpid_single_context_global(vpid_type vpid)
    {
        uint64_t descriptor[2] = { vpid, 0 };
        if (!_invvpid(3, static_cast<void *>(descriptor))) {
            throw std::runtime_error("vm::invvpid_single_context_global failed");
        }
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
        if (!_vmclear(ptr)) {
            throw std::runtime_error("vm::clear failed");
        }
    }

    inline void load(gsl::not_null<void *> ptr)
    {
        if (!_vmptrld(ptr)) {
            throw std::runtime_error("vm::load failed");
        }
    }

    inline void store(gsl::not_null<void *> ptr)
    {
        if (!_vmptrst(ptr)) {
            throw std::runtime_error("vm::store failed");
        }
    }

    inline auto read(field_type field, name_type name = "")
    {
        value_type value = {};

        if (!_vmread(field, &value))
        {
            bferror_info(0, "vm::read failed");
            bferror_subtext(0, "field", name);

            throw std::runtime_error("vm::read failed");
        }

        return value;
    }

    inline void write(field_type field, value_type value, name_type name = "")
    {
        if (!_vmwrite(field, value))
        {
            bferror_info(0, "vm::write failed");
            bferror_subtext(0, "field", name);
            bferror_subnhex(0, "value", value);

            throw std::runtime_error("vm::write failed");
        }
    }

    inline void launch_demote()
    {
        if (!_vmlaunch_demote()) {
            throw std::runtime_error("vm::launch_demote failed");
        }
    }

    inline uintptr_t call(uintptr_t r1 = 0, uintptr_t r2 = 0, uintptr_t r3 = 0, uintptr_t r4 = 0)
    { return _vmcall(r1, r2, r3, r4); }

    inline uintptr_t call(uintptr_t *r1)
    { return _vmcall1(r1); }

    inline uintptr_t call(uintptr_t *r1, uintptr_t *r2)
    { return _vmcall2(r1, r2); }

    inline uintptr_t call(uintptr_t *r1, uintptr_t *r2, uintptr_t *r3)
    { return _vmcall3(r1, r2, r3); }

    inline uintptr_t call(uintptr_t *r1, uintptr_t *r2, uintptr_t *r3, uintptr_t *r4)
    { return _vmcall4(r1, r2, r3, r4); }
}
}

// *INDENT-ON*

#endif
