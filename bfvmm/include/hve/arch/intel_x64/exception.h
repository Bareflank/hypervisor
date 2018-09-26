//
// Bareflank Hypervisor
//
// Copyright (C) 2018 Assured Information Security, Inc.
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

#ifndef EXCEPTION_INTEL_X64_H
#define EXCEPTION_INTEL_X64_H

#include "../x64/idt.h"

// *INDENT-OFF*

/// @cond

extern const char *
vector_to_str(uint64_t vec) noexcept;

extern "C" EXPORT_SYM void
default_esr(
    uint64_t vector, uint64_t ec, bool ec_valid, uint64_t *regs) noexcept;

extern "C" void
set_default_esrs(
    bfvmm::x64::idt *idt, bfvmm::x64::idt::selector_type selector);

extern "C" void _esr0(void) noexcept;
extern "C" void _esr1(void) noexcept;
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
