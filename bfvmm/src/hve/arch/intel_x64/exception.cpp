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

#include <bfgsl.h>
#include <bfdebug.h>

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/exception.h>

#include <intrinsics.h>

extern "C" void unlock_write(void);

const char *
vector_to_str(uint64_t vec) noexcept
{
    switch (vec) {
        case 0x00: return "fault: divide by 0";
        case 0x01: return "fault/trap: debug exception";
        case 0x02: return "interrupt: nmi";
        case 0x03: return "trap: breakpoint";
        case 0x04: return "trap: overflow";
        case 0x05: return "fault: bound range exceeded";
        case 0x06: return "fault: invalid opcode";
        case 0x07: return "fault: device not available (no math coprocessor";
        case 0x08: return "abort: double fault";
        case 0x09: return "fault: coprocessor segment overrun";
        case 0x0A: return "fault: invalid TSS";
        case 0x0B: return "fault: segment not present";
        case 0x0C: return "fault: stack segment fault";
        case 0x0D: return "fault: general protection fault";
        case 0x0E: return "fault: page fault";
        case 0x10: return "fault: x87 fpu floating point error";
        case 0x11: return "fault: alignment check";
        case 0x12: return "abort: machine check";
        case 0x13: return "fault: simd floating point exception";
        case 0x14: return "fault: virtualization exception";
        default: return "undefined";
    }
}

extern "C" void
default_esr(
    uint64_t vector, uint64_t ec, bool ec_valid, uint64_t *regs, void *vcpu) noexcept
{
    // -------------------------------------------------------------------------
    // NMIs
    // -------------------------------------------------------------------------

    if (vector == 2) {
        static_cast<bfvmm::intel_x64::vcpu *>(vcpu)->queue_nmi();
        return;
    }

    // -------------------------------------------------------------------------
    // Everything Else (i.e. Errors)
    // -------------------------------------------------------------------------

    unlock_write();
    auto view = gsl::span<uint64_t>(regs, 37);

    bfdebug_transaction(0, [&](std::string * msg) {

        bferror_lnbr(0, msg);
        bferror_lnbr(0, msg);
        bferror_lnbr(0, msg);
        bferror_info(0, "###############################################################", msg);
        bferror_info(0, "# FATAL: VMM Exception Caught (Host State)                    #", msg);
        bferror_info(0, "###############################################################", msg);

        bferror_lnbr(0, msg);
        if (vector == 0x0E && ::intel_x64::cr2::get() == 0) {
            bferror_info(0, "fault: null dereference", msg);
        }
        else {
            bferror_info(0, vector_to_str(vector), msg);
        }
        bferror_brk1(0, msg);

        if (ec_valid) {
            bferror_lnbr(0, msg);
            bferror_info(0, "error code", msg);
            bferror_subnhex(0, "val", ec, msg);
        }

        bferror_lnbr(0, msg);
        bferror_info(0, "general purpose registers", msg);
        bferror_subnhex(0, "rax", view[14], msg);
        bferror_subnhex(0, "rbx", view[13], msg);
        bferror_subnhex(0, "rcx", view[12], msg);
        bferror_subnhex(0, "rdx", view[11], msg);
        bferror_subnhex(0, "rbp", view[10], msg);
        bferror_subnhex(0, "rsi", view[9], msg);
        bferror_subnhex(0, "rdi", view[8], msg);
        bferror_subnhex(0, "r08", view[7], msg);
        bferror_subnhex(0, "r09", view[6], msg);
        bferror_subnhex(0, "r10", view[5], msg);
        bferror_subnhex(0, "r11", view[4], msg);
        bferror_subnhex(0, "r12", view[3], msg);
        bferror_subnhex(0, "r13", view[2], msg);
        bferror_subnhex(0, "r14", view[1], msg);
        bferror_subnhex(0, "r15", view[0], msg);
        if (ec_valid) {
            bferror_subnhex(0, "rip", view[32], msg);
            bferror_subnhex(0, "rsp", view[35], msg);
        }
        else {
            bferror_subnhex(0, "rip", view[31], msg);
            bferror_subnhex(0, "rsp", view[34], msg);
        }

        bferror_lnbr(0, msg);
        bferror_info(0, "control registers", msg);
        bferror_subnhex(0, "cr0", ::intel_x64::cr0::get(), msg);
        bferror_subnhex(0, "cr2", ::intel_x64::cr2::get(), msg);
        bferror_subnhex(0, "cr3", ::intel_x64::cr3::get(), msg);
        bferror_subnhex(0, "cr4", ::intel_x64::cr4::get(), msg);

        bferror_lnbr(0, msg);
        bferror_lnbr(0, msg);
        bferror_lnbr(0, msg);
        bferror_info(0, "###############################################################", msg);
        bferror_info(0, "# FATAL: VMM Exception Caught (Guest State)                   #", msg);
        bferror_info(0, "###############################################################", msg);
    });

    static_cast<bfvmm::intel_x64::vcpu *>(vcpu)->halt();
}

// -----------------------------------------------------------------------------
// Populate the exception handlers
// -----------------------------------------------------------------------------

void set_default_esrs(
    bfvmm::x64::idt *idt,
    bfvmm::x64::idt::selector_type selector)
{
    idt->set(0, _esr0, selector);
    idt->set(1, _esr1, selector);
    idt->set(2, _esr2, selector);
    idt->set(3, _esr3, selector);
    idt->set(4, _esr4, selector);
    idt->set(5, _esr5, selector);
    idt->set(6, _esr6, selector);
    idt->set(7, _esr7, selector);
    idt->set(8, _esr8, selector);
    idt->set(9, _esr9, selector);
    idt->set(10, _esr10, selector);
    idt->set(11, _esr11, selector);
    idt->set(12, _esr12, selector);
    idt->set(13, _esr13, selector);
    idt->set(14, _esr14, selector);
    idt->set(15, _esr15, selector);
    idt->set(16, _esr16, selector);
    idt->set(17, _esr17, selector);
    idt->set(18, _esr18, selector);
    idt->set(19, _esr19, selector);
    idt->set(20, _esr20, selector);
    idt->set(21, _esr21, selector);
    idt->set(22, _esr22, selector);
    idt->set(23, _esr23, selector);
    idt->set(24, _esr24, selector);
    idt->set(25, _esr25, selector);
    idt->set(26, _esr26, selector);
    idt->set(27, _esr27, selector);
    idt->set(28, _esr28, selector);
    idt->set(29, _esr29, selector);
    idt->set(30, _esr30, selector);
    idt->set(31, _esr31, selector);
}
