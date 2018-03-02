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

#include <support/arch/intel_x64/test_support.h>

TEST_CASE("support")
{
    CHECK_NOTHROW(_read_msr(0));
    CHECK_NOTHROW(_write_msr(0, 0));

    CHECK_NOTHROW(_read_cr0());
    CHECK_NOTHROW(_read_cr3());
    CHECK_NOTHROW(_read_cr4());
    CHECK_NOTHROW(_write_cr0(0));
    CHECK_NOTHROW(_write_cr3(0));
    CHECK_NOTHROW(_write_cr4(0));

    CHECK_NOTHROW(_read_dr7());
    CHECK_NOTHROW(_write_dr7(0));

    CHECK_NOTHROW(_read_rflags());
    CHECK_NOTHROW(_write_rflags(0));

    CHECK_NOTHROW(_read_es());
    CHECK_NOTHROW(_read_cs());
    CHECK_NOTHROW(_read_ss());
    CHECK_NOTHROW(_read_ds());
    CHECK_NOTHROW(_read_fs());
    CHECK_NOTHROW(_read_gs());
    CHECK_NOTHROW(_read_tr());
    CHECK_NOTHROW(_read_ldtr());

    CHECK_NOTHROW(_write_es(0));
    CHECK_NOTHROW(_write_cs(0));
    CHECK_NOTHROW(_write_ss(0));
    CHECK_NOTHROW(_write_ds(0));
    CHECK_NOTHROW(_write_fs(0));
    CHECK_NOTHROW(_write_gs(0));
    CHECK_NOTHROW(_write_tr(0));
    CHECK_NOTHROW(_write_ldtr(0));

    CHECK_NOTHROW(_read_gdt(&g_gdtr));
    CHECK_NOTHROW(_read_idt(&g_gdtr));

    CHECK_NOTHROW(_stop());
    CHECK_NOTHROW(_wbinvd());
    CHECK_NOTHROW(_invlpg(nullptr));

    CHECK_NOTHROW(_cpuid(nullptr, nullptr, nullptr, nullptr));
    CHECK_NOTHROW(_cpuid_eax(0));
    CHECK_NOTHROW(_cpuid_subebx(0, 0));
    CHECK_NOTHROW(_cpuid_ecx(0));

    CHECK_NOTHROW(_vmptrld(nullptr));
    CHECK_NOTHROW(_vmlaunch_demote());
    CHECK_NOTHROW(_vmxon(nullptr));
    CHECK_NOTHROW(_vmxoff());

    CHECK_NOTHROW(vmcs_launch(nullptr));
    CHECK_NOTHROW(vmcs_promote(nullptr, nullptr));
    CHECK_NOTHROW(vmcs_resume(nullptr));

    CHECK_NOTHROW(thread_context_cpuid());
    CHECK_NOTHROW(thread_context_tlsptr());

    CHECK_NOTHROW(exit_handler_entry());
}
