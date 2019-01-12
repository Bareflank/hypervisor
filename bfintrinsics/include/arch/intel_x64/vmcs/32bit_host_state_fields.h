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

#ifndef VMCS_INTEL_X64_32BIT_HOST_STATE_FIELD_H
#define VMCS_INTEL_X64_32BIT_HOST_STATE_FIELD_H

#include <arch/intel_x64/vmcs/helpers.h>

/// Intel x86_64 VMCS 32-bit Host-State Data Fields
///
/// The following provides the interface for the 32-bit host-state VMCS
/// fields as defined in Appendix B.3.4, Vol. 3 of the Intel Software Developer's
/// Manual.
///

// *INDENT-OFF*

namespace intel_x64
{
namespace vmcs
{

namespace host_ia32_sysenter_cs
{
    constexpr const auto addr = 0x0000000000004C00ULL;
    constexpr const auto name = "host_ia32_sysenter_cs";

    inline bool exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level, std::string *msg = nullptr)
    { dump_vmcs_nhex(level, msg); }
}

}
}

// *INDENT-ON*

#endif
