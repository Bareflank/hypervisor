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

#ifndef VMM_H
#define VMM_H

#include <bfgsl.h>
#include <bfarch.h>
#include <bfdebug.h>
#include <bfexports.h>
#include <bfcallonce.h>
#include <bfexception.h>

#ifdef BF_X64
#include "hve/arch/x64/gdt.h"
#include "hve/arch/x64/idt.h"
#include "hve/arch/x64/tss.h"
#include "hve/arch/x64/unmapper.h"
#endif

#ifdef BF_INTEL_X64
#include "hve/arch/intel_x64/vmexit/control_register.h"
#include "hve/arch/intel_x64/vmexit/cpuid.h"
#include "hve/arch/intel_x64/vmexit/ept_violation.h"
#include "hve/arch/intel_x64/vmexit/external_interrupt.h"
#include "hve/arch/intel_x64/vmexit/init_signal.h"
#include "hve/arch/intel_x64/vmexit/interrupt_window.h"
#include "hve/arch/intel_x64/vmexit/io_instruction.h"
#include "hve/arch/intel_x64/vmexit/monitor_trap.h"
#include "hve/arch/intel_x64/vmexit/nmi_window.h"
#include "hve/arch/intel_x64/vmexit/nmi.h"
#include "hve/arch/intel_x64/vmexit/preemption_timer.h"
#include "hve/arch/intel_x64/vmexit/rdmsr.h"
#include "hve/arch/intel_x64/vmexit/sipi_signal.h"
#include "hve/arch/intel_x64/vmexit/wrmsr.h"
#include "hve/arch/intel_x64/vmexit/xsetbv.h"
#include "hve/arch/intel_x64/check.h"
#include "hve/arch/intel_x64/ept.h"
#include "hve/arch/intel_x64/exception.h"
#include "hve/arch/intel_x64/exit_handler.h"
#include "hve/arch/intel_x64/interrupt_queue.h"
#include "hve/arch/intel_x64/microcode.h"
#include "hve/arch/intel_x64/mtrrs.h"
#include "hve/arch/intel_x64/vcpu_global_state.h"
#include "hve/arch/intel_x64/vcpu_state.h"
#include "hve/arch/intel_x64/vcpu.h"
#include "hve/arch/intel_x64/vmx.h"
#include "hve/arch/intel_x64/vpid.h"
#endif

#ifdef BF_X64
#include "memory_manager/arch/x64/cr3.h"
#endif

#include "memory_manager/buddy_allocator.h"
#include "memory_manager/memory_manager.h"
#include "memory_manager/object_allocator.h"

#include "vcpu/vcpu.h"
#include "vcpu/vcpu_factory.h"
#include "vcpu/vcpu_manager.h"

#ifdef BF_INTEL_X64
using namespace bfvmm::intel_x64;
#endif

#endif
