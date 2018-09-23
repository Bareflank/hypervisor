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

/// @cond

#ifndef TEST_SUPPORT_H
#define TEST_SUPPORT_H

#include <set>
#include <map>
#include <vector>

#include <bfarch.h>

#include "intrinsics.h"

#include "hve.h"
#include "memory_manager.h"
#include "misc.h"

struct quiet {
    quiet()
    { unsafe_write_cstr(nullptr, 0); }
};

quiet g_quite{};

void setup_test_support()
{
#ifdef BF_X64
    setup_registers_x64();
    setup_gdt_x64();
    setup_idt_x64();
#endif

#ifdef BF_INTEL_X64
    setup_registers_intel_x64();
    setup_msrs_intel_x64();
    setup_cpuid_intel_x64();
#endif
}

#endif

/// @endcond
