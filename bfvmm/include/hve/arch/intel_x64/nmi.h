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

#ifndef NMI_INTEL_X64_H
#define NMI_INTEL_X64_H

#include <bfexports.h>
#include "../x64/idt.h"

/// _handle_nmi
///
/// The NMI handler referenced by vector 2 of the IDT
/// Enables NMI-window exiting
///
extern "C" void _handle_nmi(void) noexcept;

/// set_nmi_handler
///
/// @param idt the address of the IDT
/// @param selector the selector of the IDT descriptor
///
void set_nmi_handler(
    bfvmm::x64::idt *idt,
    bfvmm::x64::idt::selector_type selector
) noexcept;

/// inject_nmi
///
/// Program the VMCS to inject an NMI on VM-entry.
/// This should only be called from an NMI-window exit handler.
///
void inject_nmi() noexcept;

#endif
