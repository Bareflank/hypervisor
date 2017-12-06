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

#include <catch/catch.hpp>
#include <intrinsics/x86/common_x64.h>
#include <intrinsics/x86/intel_x64.h>

TEST_CASE("cache_mock_invd")
{
    CHECK_NOTHROW(_invd());
}

TEST_CASE("cache_mock_wbinvd")
{
    CHECK_NOTHROW(_wbinvd());
}

TEST_CASE("cache_mock_clflush")
{
    uint32_t addr = 0x00000000U;
    CHECK_NOTHROW(_clflush(&addr));
}

TEST_CASE("cpuid_mock_cpuid_eax")
{
    uint32_t val = 0x00000000U;
    CHECK_NOTHROW(_cpuid_eax(val));
}

TEST_CASE("cpuid_mock_cpuid_ebx")
{
    uint32_t val = 0x00000000U;
    CHECK_NOTHROW(_cpuid_ebx(val));
}

TEST_CASE("cpuid_mock_cpuid_ecx")
{
    uint32_t val = 0x00000000U;
    CHECK_NOTHROW(_cpuid_ecx(val));
}

TEST_CASE("cpuid_mock_cpuid_edx")
{
    uint32_t val = 0x00000000U;
    CHECK_NOTHROW(_cpuid_edx(val));
}

TEST_CASE("cpuid_mock_cpuid_subeax")
{
    uint32_t val = 0x00000000U;
    uint32_t sub = 0x00000000U;
    CHECK_NOTHROW(_cpuid_subeax(val, sub));
}

TEST_CASE("cpuid_mock_cpuid_subebx")
{
    uint32_t val = 0x00000000U;
    uint32_t sub = 0x00000000U;
    CHECK_NOTHROW(_cpuid_subebx(val, sub));
}

TEST_CASE("cpuid_mock_cpuid_subecx")
{
    uint32_t val = 0x00000000U;
    uint32_t sub = 0x00000000U;
    CHECK_NOTHROW(_cpuid_subecx(val, sub));
}

TEST_CASE("cpuid_mock_cpuid_subedx")
{
    uint32_t val = 0x00000000U;
    uint32_t sub = 0x00000000U;
    CHECK_NOTHROW(_cpuid_subedx(val, sub));
}

TEST_CASE("cpuid_mock_cpuid")
{
    uint32_t eax = 0x00000000U;
    uint32_t ebx = 0x00000000U;
    uint32_t ecx = 0x00000000U;
    uint32_t edx = 0x00000000U;
    CHECK_NOTHROW(_cpuid(&eax, &ebx, &ecx, &edx));
}

TEST_CASE("crs_intel_mock_read_cr0")
{
    CHECK_NOTHROW(_read_cr0());
}

TEST_CASE("crs_intel_mock_write_cr0")
{
    uint64_t val = 0x0;
    CHECK_NOTHROW(_write_cr0(val));
}

TEST_CASE("crs_intel_mock_read_cr2")
{
    CHECK_NOTHROW(_read_cr2());
}

TEST_CASE("crs_intel_mock_write_cr2")
{
    uint64_t val = 0x0;
    CHECK_NOTHROW(_write_cr2(val));
}

TEST_CASE("crs_intel_mock_read_cr3")
{
    CHECK_NOTHROW(_read_cr3());
}

TEST_CASE("crs_intel_mock_write_cr3")
{
    uint64_t val = 0x0;
    CHECK_NOTHROW(_write_cr3(val));
}

TEST_CASE("crs_intel_mock_read_cr4")
{
    CHECK_NOTHROW(_read_cr4());
}

TEST_CASE("crs_intel_mock_write_cr4")
{
    uint64_t val = 0x0;
    CHECK_NOTHROW(_write_cr4(val));
}

TEST_CASE("crs_intel_mock_read_cr8")
{
    CHECK_NOTHROW(_read_cr8());
}

TEST_CASE("crs_intel_mock_write_cr8")
{
    uint64_t val = 0x0;
    CHECK_NOTHROW(_write_cr8(val));
}

TEST_CASE("debug_mock_read_dr7")
{
    CHECK_NOTHROW(_read_dr7());
}

TEST_CASE("debug_mock_write_dr7")
{
    uint64_t val = 0x0;
    CHECK_NOTHROW(_write_dr7(val));
}

TEST_CASE("fence_mock_sfence")
{
    CHECK_NOTHROW(_sfence());
}

TEST_CASE("gdt_mock_read_gdt")
{
    gdt_reg_x64_t g_gdt;
    CHECK_NOTHROW(_read_gdt(&g_gdt));
}

TEST_CASE("gdt_mock_write_gdt")
{
    gdt_reg_x64_t g_gdt;
    CHECK_NOTHROW(_write_gdt(&g_gdt));
}

TEST_CASE("idt_mock_read_idt")
{
    idt_reg_x64_t g_idt;
    CHECK_NOTHROW(_read_idt(&g_idt));
}

TEST_CASE("idt_mock_write_idt")
{
    idt_reg_x64_t g_idt;
    CHECK_NOTHROW(_write_idt(&g_idt));
}

TEST_CASE("msrs_mock_read_msr")
{
    uint32_t addr = 0x0;
    CHECK_NOTHROW(_read_msr(addr));
}

TEST_CASE("msrs_mock_write_msr")
{
    uint32_t addr = 0x0;
    uint64_t val = 0x0;
    CHECK_NOTHROW(_write_msr(addr, val));
}

TEST_CASE("pm_mock_halt")
{
    CHECK_NOTHROW(_halt());
}

TEST_CASE("pm_mock_stop")
{
    CHECK_NOTHROW(_stop());
}

TEST_CASE("portio_mock_inb")
{
    uint16_t port = 0;
    CHECK_NOTHROW(_inb(port));
}

TEST_CASE("portio_mock_inw")
{
    uint16_t port = 0;
    CHECK_NOTHROW(_inw(port));
}

TEST_CASE("portio_mock_ind")
{
    uint16_t port = 0;
    CHECK_NOTHROW(_ind(port));
}

TEST_CASE("portio_mock_insb")
{
    uint16_t port = 0;
    uint64_t m8 = 0;
    CHECK_NOTHROW(_insb(port, m8));
}

TEST_CASE("portio_mock_insw")
{
    uint16_t port = 0;
    uint64_t m16 = 0;
    CHECK_NOTHROW(_insw(port, m16));
}

TEST_CASE("portio_mock_insd")
{
    uint16_t port = 0;
    uint64_t m32 = 0;
    CHECK_NOTHROW(_insd(port, m32));
}

TEST_CASE("portio_mock_insbrep")
{
    uint16_t port = 0;
    uint64_t m8 = 0;
    uint32_t count = 0;
    CHECK_NOTHROW(_insbrep(port, m8, count));
}

TEST_CASE("portio_mock_inswrep")
{
    uint16_t port = 0;
    uint64_t m16 = 0;
    uint32_t count = 0;
    CHECK_NOTHROW(_inswrep(port, m16, count));
}

TEST_CASE("portio_mock_insdrep")
{
    uint16_t port = 0;
    uint64_t m32 = 0;
    uint32_t count = 0;
    CHECK_NOTHROW(_insdrep(port, m32, count));
}

TEST_CASE("portio_mock_outb")
{
    uint16_t port = 0;
    uint8_t val = 0;
    CHECK_NOTHROW(_outb(port, val));
}

TEST_CASE("portio_mock_outw")
{
    uint16_t port = 0;
    uint16_t val = 0;
    CHECK_NOTHROW(_outw(port, val));
}

TEST_CASE("portio_mock_outd")
{
    uint16_t port = 0;
    uint32_t val = 0;
    CHECK_NOTHROW(_outd(port, val));
}

TEST_CASE("portio_mock_outsb")
{
    uint16_t port = 0;
    uint64_t m8 = 0;
    CHECK_NOTHROW(_outsb(port, m8));
}

TEST_CASE("portio_mock_outsw")
{
    uint16_t port = 0;
    uint64_t m16 = 0;
    CHECK_NOTHROW(_outsw(port, m16));
}

TEST_CASE("portio_mock_outsd")
{
    uint16_t port = 0;
    uint64_t m32 = 0;
    CHECK_NOTHROW(_outsd(port, m32));
}

TEST_CASE("portio_mock_outsbrep")
{
    uint16_t port = 0;
    uint64_t m8 = 0;
    uint32_t count = 0;
    CHECK_NOTHROW(_outsbrep(port, m8, count));
}

TEST_CASE("portio_mock_outswrep")
{
    uint16_t port = 0;
    uint64_t m16 = 0;
    uint32_t count = 0;
    CHECK_NOTHROW(_outswrep(port, m16, count));
}

TEST_CASE("portio_mock_outsdrep")
{
    uint16_t port = 0;
    uint64_t m32 = 0;
    uint32_t count = 0;
    CHECK_NOTHROW(_outsdrep(port, m32, count));
}

TEST_CASE("rdtsc_mock_read_tsc")
{
    CHECK_NOTHROW(_read_tsc());
}

TEST_CASE("rdtsc_mock_read_tscp")
{
    CHECK_NOTHROW(_read_tscp());
}

TEST_CASE("rflags_mock_read_rflags")
{
    CHECK_NOTHROW(_read_rflags());
}

TEST_CASE("rflags_mock_write_rflags")
{
    uint64_t val = 0;
    CHECK_NOTHROW(_write_rflags(val));
}

TEST_CASE("srs_mock_read_es")
{
    CHECK_NOTHROW(_read_es());
}

TEST_CASE("srs_mock_write_es")
{
    uint16_t val = 0;
    CHECK_NOTHROW(_write_es(val));
}

TEST_CASE("srs_mock_read_cs")
{
    CHECK_NOTHROW(_read_cs());
}

TEST_CASE("srs_mock_write_cs")
{
    uint16_t val = 0;
    CHECK_NOTHROW(_write_cs(val));
}

TEST_CASE("srs_mock_read_ss")
{
    CHECK_NOTHROW(_read_ss());
}

TEST_CASE("srs_mock_write_ss")
{
    uint16_t val = 0;
    CHECK_NOTHROW(_write_ss(val));
}

TEST_CASE("srs_mock_read_ds")
{
    CHECK_NOTHROW(_read_ds());
}

TEST_CASE("srs_mock_write_ds")
{
    uint16_t val = 0;
    CHECK_NOTHROW(_write_ds(val));
}

TEST_CASE("srs_mock_read_fs")
{
    CHECK_NOTHROW(_read_fs());
}

TEST_CASE("srs_mock_write_fs")
{
    uint16_t val = 0;
    CHECK_NOTHROW(_write_fs(val));
}

TEST_CASE("srs_mock_read_gs")
{
    CHECK_NOTHROW(_read_gs());
}

TEST_CASE("srs_mock_write_gs")
{
    uint16_t val = 0;
    CHECK_NOTHROW(_write_gs(val));
}

TEST_CASE("srs_mock_read_ldtr")
{
    CHECK_NOTHROW(_read_ldtr());
}

TEST_CASE("srs_mock_write_ldtr")
{
    uint16_t val = 0;
    CHECK_NOTHROW(_write_ldtr(val));
}

TEST_CASE("srs_mock_read_tr")
{
    CHECK_NOTHROW(_read_tr());
}

TEST_CASE("srs_mock_write_tr")
{
    uint16_t val = 0;
    CHECK_NOTHROW(_write_tr(val));
}

TEST_CASE("thread_context_mock_thread_context_cpuid")
{
    CHECK_NOTHROW(thread_context_cpuid());
}

TEST_CASE("thread_context_mock_thread_context_tlsptr")
{
    CHECK_NOTHROW(thread_context_tlsptr());
}

TEST_CASE("tlb_mock_invlpg")
{
    uint32_t virt = 0;
    CHECK_NOTHROW(_invlpg(&virt));
}

TEST_CASE("vmx_intel_mock_vmxon")
{
    uint32_t ptr = 0;
    CHECK_NOTHROW(_vmxon(&ptr));
}

TEST_CASE("vmx_intel_mock_vmxoff")
{
    CHECK_NOTHROW(_vmxoff());
}

TEST_CASE("vmx_intel_mock_vmclear")
{
    uint32_t ptr = 0;
    CHECK_NOTHROW(_vmclear(&ptr));
}

TEST_CASE("vmx_intel_mock_vmptrld")
{
    uint32_t ptr = 0;
    CHECK_NOTHROW(_vmptrld(&ptr));
}

TEST_CASE("vmx_intel_mock_vmptrst")
{
    uint32_t ptr = 0;
    CHECK_NOTHROW(_vmptrst(&ptr));
}

TEST_CASE("vmx_intel_mock_vmread")
{
    uint64_t field = 0;
    uint64_t val = 0;
    CHECK_NOTHROW(_vmread(field, &val));
}

TEST_CASE("vmx_intel_mock_vmwrite")
{
    uint64_t field = 0;
    uint64_t val = 0;
    CHECK_NOTHROW(_vmwrite(field, val));
}

TEST_CASE("vmx_intel_mock_vmlaunch_demote")
{
    CHECK_NOTHROW(_vmlaunch_demote());
}

TEST_CASE("vmx_intel_mock_invept")
{
    uint64_t field = 0;
    uint64_t ptr = 0;
    CHECK_NOTHROW(_invept(field, &ptr));
}

TEST_CASE("vmx_intel_mock_invvpid")
{
    uint64_t field = 0;
    uint64_t ptr = 0;
    CHECK_NOTHROW(_invvpid(field, &ptr));
}
