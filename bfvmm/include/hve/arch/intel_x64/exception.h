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

#ifndef EXCEPTION_INTEL_X64_H
#define EXCEPTION_INTEL_X64_H

#include "../x64/idt.h"

// *INDENT-OFF*

/// @cond

extern const char *
vector_to_str(uint64_t vec) noexcept;

extern "C" void
default_esr(
    uint64_t vector, uint64_t ec, bool ec_valid, uint64_t *regs, void *vcpu) noexcept;

extern "C" void
set_default_esrs(
    bfvmm::x64::idt *idt, bfvmm::x64::idt::selector_type selector);

extern "C" void _esr0(void) noexcept;
extern "C" void _esr1(void) noexcept;
extern "C" void _esr2(void) noexcept;
extern "C" void _esr3(void) noexcept;
extern "C" void _esr4(void) noexcept;
extern "C" void _esr5(void) noexcept;
extern "C" void _esr6(void) noexcept;
extern "C" void _esr7(void) noexcept;
extern "C" void _esr8(void) noexcept;
extern "C" void _esr9(void) noexcept;
extern "C" void _esr10(void) noexcept;
extern "C" void _esr11(void) noexcept;
extern "C" void _esr12(void) noexcept;
extern "C" void _esr13(void) noexcept;
extern "C" void _esr14(void) noexcept;
extern "C" void _esr15(void) noexcept;
extern "C" void _esr16(void) noexcept;
extern "C" void _esr17(void) noexcept;
extern "C" void _esr18(void) noexcept;
extern "C" void _esr19(void) noexcept;
extern "C" void _esr20(void) noexcept;
extern "C" void _esr21(void) noexcept;
extern "C" void _esr22(void) noexcept;
extern "C" void _esr23(void) noexcept;
extern "C" void _esr24(void) noexcept;
extern "C" void _esr25(void) noexcept;
extern "C" void _esr26(void) noexcept;
extern "C" void _esr27(void) noexcept;
extern "C" void _esr28(void) noexcept;
extern "C" void _esr29(void) noexcept;
extern "C" void _esr30(void) noexcept;
extern "C" void _esr31(void) noexcept;

/// @endcond

// *INDENT-ON*

#endif
