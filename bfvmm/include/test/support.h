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
