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

#ifdef BF_X64

#include "../hve/arch/x64/gdt.h"
#include "../hve/arch/x64/idt.h"

std::vector<bfvmm::x64::gdt::segment_descriptor_type> g_gdt = {
    0x0,
    0xFF7FFFFFFFFFFFFF,
    0xFF7FFFFFFFFFFFFF,
    0xFF7FFFFFFFFFFFFF,
    0xFF7FFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFF8FFFFFFFFFFF,
    0x00000000FFFFFFFF,
};

std::vector<bfvmm::x64::idt::interrupt_descriptor_type> g_idt = {
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF
};

void
setup_gdt_x64()
{
    auto limit = g_gdt.size() * sizeof(bfvmm::x64::gdt::segment_descriptor_type) - 1;

    g_gdtr.base = reinterpret_cast<uint64_t>(&g_gdt.at(0));
    g_gdtr.limit = gsl::narrow_cast<uint16_t>(limit);
}

void
setup_idt_x64()
{
    auto limit = g_idt.size() * sizeof(bfvmm::x64::idt::interrupt_descriptor_type) - 1;

    g_idtr.base = reinterpret_cast<uint64_t>(&g_idt.at(0));
    g_idtr.limit = gsl::narrow_cast<uint16_t>(limit);
}

#endif

#ifdef BF_INTEL_X64

#include "../hve/arch/intel_x64/vmx.h"
#include "../hve/arch/intel_x64/vmcs.h"
#include "../hve/arch/intel_x64/check.h"
#include "../hve/arch/intel_x64/exception.h"
#include "../hve/arch/intel_x64/exit_handler.h"
#include "../hve/arch/intel_x64/vcpu.h"

bfvmm::intel_x64::save_state_t g_save_state{};

extern "C" void vmcs_launch(
    bfvmm::intel_x64::save_state_t *save_state) noexcept
{ bfignored(save_state); }

extern "C" void vmcs_promote(
    bfvmm::intel_x64::save_state_t *save_state, const void *gdt) noexcept
{ bfignored(save_state); bfignored(gdt); }

extern "C" void vmcs_resume(
    bfvmm::intel_x64::save_state_t *save_state) noexcept
{ bfignored(save_state); }

extern "C" void exit_handler_entry(void)
{ }

#endif

/// @endcond
