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

#include <intrinsics.h>

#ifdef BF_X64

std::map<uint32_t, uint64_t> g_msrs;
std::map<uint32_t, uint32_t> g_eax_cpuid;
std::map<uint32_t, uint32_t> g_ebx_cpuid;
std::map<uint32_t, uint32_t> g_ecx_cpuid;
std::map<uint32_t, uint32_t> g_edx_cpuid;
std::map<x64::portio::port_addr_type, x64::portio::port_32bit_type> g_ports;

x64::rflags::value_type g_rflags = 0;

uint16_t g_es;
uint16_t g_cs;
uint16_t g_ss;
uint16_t g_ds;
uint16_t g_fs;
uint16_t g_gs;
uint16_t g_ldtr;
uint16_t g_tr;

::x64::gdt_reg::reg_t g_gdtr{};
::x64::idt_reg::reg_t g_idtr{};

extern "C" void _handle_nmi(void) noexcept {}

extern "C" void _esr0(void) noexcept {}
extern "C" void _esr1(void) noexcept {}
extern "C" void _esr3(void) noexcept {}
extern "C" void _esr4(void) noexcept {}
extern "C" void _esr5(void) noexcept {}
extern "C" void _esr6(void) noexcept {}
extern "C" void _esr7(void) noexcept {}
extern "C" void _esr8(void) noexcept {}
extern "C" void _esr9(void) noexcept {}
extern "C" void _esr10(void) noexcept {}
extern "C" void _esr11(void) noexcept {}
extern "C" void _esr12(void) noexcept {}
extern "C" void _esr13(void) noexcept {}
extern "C" void _esr14(void) noexcept {}
extern "C" void _esr15(void) noexcept {}
extern "C" void _esr16(void) noexcept {}
extern "C" void _esr17(void) noexcept {}
extern "C" void _esr18(void) noexcept {}
extern "C" void _esr19(void) noexcept {}
extern "C" void _esr20(void) noexcept {}
extern "C" void _esr21(void) noexcept {}
extern "C" void _esr22(void) noexcept {}
extern "C" void _esr23(void) noexcept {}
extern "C" void _esr24(void) noexcept {}
extern "C" void _esr25(void) noexcept {}
extern "C" void _esr26(void) noexcept {}
extern "C" void _esr27(void) noexcept {}
extern "C" void _esr28(void) noexcept {}
extern "C" void _esr29(void) noexcept {}
extern "C" void _esr30(void) noexcept {}
extern "C" void _esr31(void) noexcept {}

extern "C" uint64_t
_read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

extern "C" void
_write_msr(uint32_t addr, uint64_t val) noexcept
{ g_msrs[addr] = val; }

extern "C" uint64_t
_read_rflags(void) noexcept
{ return g_rflags; }

extern "C" void
_write_rflags(uint64_t val) noexcept
{ g_rflags = val; }

extern "C" uint16_t
_read_es() noexcept
{ return g_es; }

extern "C" uint16_t
_read_cs() noexcept
{ return g_cs; }

extern "C" uint16_t
_read_ss() noexcept
{ return g_ss; }

extern "C" uint16_t
_read_ds() noexcept
{ return g_ds; }

extern "C" uint16_t
_read_fs() noexcept
{ return g_fs; }

extern "C" uint16_t
_read_gs() noexcept
{ return g_gs; }

extern "C" uint16_t
_read_tr() noexcept
{ return g_tr; }

extern "C" uint16_t
_read_ldtr() noexcept
{ return g_ldtr; }

extern "C" void
_write_es(uint16_t val) noexcept
{ g_es = val; }

extern "C" void
_write_cs(uint16_t val) noexcept
{ g_cs = val; }

extern "C" void
_write_ss(uint16_t val) noexcept
{ g_ss = val; }

extern "C" void
_write_ds(uint16_t val) noexcept
{ g_ds = val; }

extern "C" void
_write_fs(uint16_t val) noexcept
{ g_fs = val; }

extern "C" void
_write_gs(uint16_t val) noexcept
{ g_gs = val; }

extern "C" void
_write_tr(uint16_t val) noexcept
{ g_tr = val; }

extern "C" void
_write_ldtr(uint16_t val) noexcept
{ g_ldtr = val; }

extern "C" void
_read_gdt(void *gdt_reg) noexcept
{ *static_cast<::x64::gdt_reg::reg_t *>(gdt_reg) = g_gdtr; }

extern "C" void
_read_idt(void *idt_reg) noexcept
{ *static_cast<::x64::idt_reg::reg_t *>(idt_reg) = g_idtr; }

extern "C" uint8_t
_inb(uint16_t port) noexcept
{ return gsl::narrow_cast<x64::portio::port_8bit_type>(g_ports[port]); }

extern "C" uint16_t
_inw(uint16_t port) noexcept
{ return gsl::narrow_cast<x64::portio::port_16bit_type>(g_ports[port]); }

extern "C" uint32_t
_ind(uint16_t port) noexcept
{ return gsl::narrow_cast<x64::portio::port_32bit_type>(g_ports[port]); }

extern "C" void
_outb(uint16_t port, uint8_t val) noexcept
{ g_ports[port] = val; }

extern "C" void
_outw(uint16_t port, uint16_t val) noexcept
{ g_ports[port] = val; }

extern "C" void
_outd(uint16_t port, uint32_t val) noexcept
{ g_ports[port] = val; }

extern "C" void
_stop() noexcept
{ }

extern "C" void
_halt() noexcept
{ }

extern "C" void
_wbinvd() noexcept
{ }

extern "C" void
_pause() noexcept
{ }

extern "C" void
_invlpg(const void *addr) noexcept
{ bfignored(addr); }

extern "C" bool
_invept(uint64_t type, void *ptr) noexcept
{ bfignored(ptr); return true; }

extern "C" bool
_invvpid(uint64_t type, void *ptr) noexcept
{ bfignored(ptr); return true; }

extern "C" void
_cpuid(void *eax, void *ebx, void *ecx, void *edx) noexcept
{
    bfignored(eax);
    bfignored(ebx);
    bfignored(ecx);
    bfignored(edx);
}

extern "C" uint32_t
_cpuid_eax(uint32_t val) noexcept
{ return g_eax_cpuid[val]; }

extern "C" uint32_t
_cpuid_subebx(uint32_t val, uint32_t sub) noexcept
{ bfignored(sub); return g_ebx_cpuid[val]; }

extern "C" uint32_t
_cpuid_ecx(uint32_t val) noexcept
{ return g_ecx_cpuid[val]; }

extern "C" uint32_t
_cpuid_edx(uint32_t val) noexcept
{ return g_edx_cpuid[val]; }

void
setup_registers_x64()
{
    g_rflags = 0x0;
}

#endif

#ifdef BF_INTEL_X64

intel_x64::cr0::value_type g_cr0 = 0;
intel_x64::cr2::value_type g_cr2 = 0;
intel_x64::cr3::value_type g_cr3 = 0;
intel_x64::cr4::value_type g_cr4 = 0;
intel_x64::cr8::value_type g_cr8 = 0;
intel_x64::dr7::value_type g_dr7 = 0;

bool g_vmload_fails = false;
bool g_vmlaunch_fails = false;
bool g_vmxon_fails = false;
bool g_vmxoff_fails = false;
bool g_write_cr4_fails = false;

std::map<uint64_t, uint64_t> g_vmcs_fields;

extern "C" uint64_t
_read_cr0(void) noexcept
{ return g_cr0; }

extern "C" uint64_t
_read_cr2(void) noexcept
{ return g_cr2; }

extern "C" uint64_t
_read_cr3(void) noexcept
{ return g_cr3; }

extern "C" uint64_t
_read_cr4(void) noexcept
{ return g_cr4; }

extern "C" uint64_t
_read_cr8(void) noexcept
{ return g_cr8; }

extern "C" void
_write_cr0(uint64_t val) noexcept
{ g_cr0 = val; }

extern "C" void
_write_cr2(uint64_t val) noexcept
{ g_cr2 = val; }

extern "C" void
_write_cr3(uint64_t val) noexcept
{ g_cr3 = val; }

extern "C" void
_write_cr4(uint64_t val) noexcept
{
    if (g_write_cr4_fails) {
        return;
    }

    g_cr4 = val;
}

extern "C" void
_write_cr8(uint64_t val) noexcept
{ g_cr8 = val; }

extern "C" void
_write_xcr0(uint64_t val) noexcept
{ bfignored(val); }

extern "C" uint64_t
_read_dr7() noexcept
{ return g_dr7; }

extern "C" void
_write_dr7(uint64_t val) noexcept
{ g_dr7 = val; }

extern "C" bool
_vmread(uint64_t field, uint64_t *value) noexcept
{
    *value = g_vmcs_fields[field];
    return true;
}

extern "C" bool
_vmwrite(uint64_t field, uint64_t value) noexcept
{
    g_vmcs_fields[field] = value;
    return true;
}

extern "C" bool
_vmptrld(void *ptr) noexcept
{ (void)ptr; return !g_vmload_fails; }

extern "C" bool
_vmlaunch_demote() noexcept
{ return !g_vmlaunch_fails; }

extern "C" bool
_vmxon(void *ptr) noexcept
{ bfignored(ptr); return !g_vmxon_fails; }

extern "C" bool
_vmxoff() noexcept
{ return !g_vmxoff_fails; }

void
setup_registers_intel_x64()
{
    g_cr0 = 0;
    g_cr2 = 0;
    g_cr3 = 0;
    g_cr4 = 0;
    g_cr8 = 0;
    g_dr7 = 0;
}

void
setup_msrs_intel_x64()
{
    g_msrs[intel_x64::msrs::ia32_vmx_basic::addr] = (1ULL << 55) | (6ULL << 50);

    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = 0xFFFFFFFF00000000UL;

    g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed0::addr] = 0U;
    g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed1::addr] = 0xFFFFFFFFFFFFFFFF;
    g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed0::addr] = 0U;
    g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed1::addr] = 0xFFFFFFFFFFFFFFFF;

    g_msrs[intel_x64::msrs::ia32_efer::addr] = intel_x64::msrs::ia32_efer::lma::mask;
    g_msrs[intel_x64::msrs::ia32_feature_control::addr] = (0x1ULL << 0);
}

void
setup_cpuid_intel_x64()
{
    g_ecx_cpuid[intel_x64::cpuid::feature_information::addr] = intel_x64::cpuid::feature_information::ecx::vmx::mask;
}

#endif

/// @endcond
