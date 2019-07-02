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

#include <hve/arch/intel_x64/vcpu.h>

namespace bfvmm::intel_x64
{

sipi_signal_handler::sipi_signal_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_exit_handler_for_reason(
        exit_reason::basic_exit_reason::sipi,
    {&sipi_signal_handler::handle, this}
    );
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
sipi_signal_handler::handle(vcpu *vcpu)
{
    using namespace vmcs_n::guest_activity_state;
    using namespace vmcs_n::vm_entry_controls;
    bfignored(vcpu);

    // .........................................................................
    // Ignore SIPI - SIPI
    // .........................................................................

    // The Intel spec states that more than one SIPI should be sent
    // to each AP in the event that the first AP is ignored. The problem
    // with this approach is that it is possible for the exit handler to
    // see both SIPIs (i.e. the second sipi is not actually dropped by
    // the CPU). If this happens, we need to emulate this drop our selves
    //

    if (vmcs_n::guest_activity_state::get() == active) {
        return true;
    }

    // .........................................................................
    // INIT
    // .........................................................................

    // TODO:
    //
    // - Currently, there are several registers that the VMCS does not control
    //   and that we are not saving in our save state that we are not resetting
    //   here. For completness, we should find a way to reset all of the
    //   registers outlined by the SDM. These registers include:
    //   - CR2
    //   - x87 FPU Control Word
    //   - x87 FPU Status Word
    //   - x87 FPU Tag Word
    //   - x87 FPU Data Operand
    //   - dr0, dr1, dr2, dr3
    //   - dr6
    //   = IA32_XSS
    //   - BNDCFGU
    //   - BND0-BND3
    //   - IA32_BNDCFGS
    //
    // - Currently, we don't set the Extended Model Value in EDX, whish is
    //   stated by the SDM. We use 0x600, which seems to work fine, but
    //   at some point, we should fill in the proper value
    //

    vmcs_n::guest_rflags::set(0x00000002);
    vcpu->set_rip(0x0000FFF0);

    vmcs_n::guest_cr0::set(0x60000010 | m_vcpu->global_state()->ia32_vmx_cr0_fixed0);
    vmcs_n::guest_cr3::set(0);
    vmcs_n::guest_cr4::set(0x00000000 | m_vcpu->global_state()->ia32_vmx_cr4_fixed0);

    vmcs_n::cr0_read_shadow::set(0x60000010);
    vmcs_n::cr4_read_shadow::set(0);

    vmcs_n::guest_cs_selector::set(0xF000);
    vmcs_n::guest_cs_base::set(0xFFFF0000);
    vmcs_n::guest_cs_limit::set(0xFFFF);
    vmcs_n::guest_cs_access_rights::set(0x9B);

    vmcs_n::guest_ss_selector::set(0);
    vmcs_n::guest_ss_base::set(0);
    vmcs_n::guest_ss_limit::set(0xFFFF);
    vmcs_n::guest_ss_access_rights::set(0x93);

    vmcs_n::guest_ds_selector::set(0);
    vmcs_n::guest_ds_base::set(0);
    vmcs_n::guest_ds_limit::set(0xFFFF);
    vmcs_n::guest_ds_access_rights::set(0x93);

    vmcs_n::guest_es_selector::set(0);
    vmcs_n::guest_es_base::set(0);
    vmcs_n::guest_es_limit::set(0xFFFF);
    vmcs_n::guest_es_access_rights::set(0x93);

    vmcs_n::guest_fs_selector::set(0);
    vmcs_n::guest_fs_base::set(0);
    vmcs_n::guest_fs_limit::set(0xFFFF);
    vmcs_n::guest_fs_access_rights::set(0x93);

    vmcs_n::guest_gs_selector::set(0);
    vmcs_n::guest_gs_base::set(0);
    vmcs_n::guest_gs_limit::set(0xFFFF);
    vmcs_n::guest_gs_access_rights::set(0x93);

    vcpu->set_rdx(0x00000600);
    vcpu->set_rax(0);
    vcpu->set_rbx(0);
    vcpu->set_rcx(0);
    vcpu->set_rsi(0);
    vcpu->set_rdi(0);
    vcpu->set_rbp(0);
    vcpu->set_rsp(0);

    vmcs_n::guest_gdtr_base::set(0);
    vmcs_n::guest_gdtr_limit::set(0xFFFF);

    vmcs_n::guest_idtr_base::set(0);
    vmcs_n::guest_idtr_limit::set(0xFFFF);

    vmcs_n::guest_ldtr_selector::set(0);
    vmcs_n::guest_ldtr_base::set(0);
    vmcs_n::guest_ldtr_limit::set(0xFFFF);
    vmcs_n::guest_ldtr_access_rights::set(0x82);

    vmcs_n::guest_tr_selector::set(0);
    vmcs_n::guest_tr_base::set(0);
    vmcs_n::guest_tr_limit::set(0xFFFF);
    vmcs_n::guest_tr_access_rights::set(0x8B);

    vmcs_n::guest_dr7::set(0x00000400);

    vcpu->set_r08(0);
    vcpu->set_r09(0);
    vcpu->set_r10(0);
    vcpu->set_r11(0);
    vcpu->set_r12(0);
    vcpu->set_r13(0);
    vcpu->set_r14(0);
    vcpu->set_r15(0);

    vmcs_n::guest_ia32_efer::set(0);
    vmcs_n::guest_fs_base::set(0);
    vmcs_n::guest_gs_base::set(0);

    ia_32e_mode_guest::disable();

    // .........................................................................
    // SIPI
    // .........................................................................

    // This is where we actually execute the SIPI logic. Most of the code here
    // overwrites some of the logic in the INIT code above, but we wanted this
    // to be easy to read and self documenting, and the extra time it takes
    // to redo some of these registers is not important.
    //
    // When a SIPI is received, the first instruction executed by the
    // guest is 0x000VV000, with VV being the vector number supplied
    // in the SIPI (hence why the first instruction needs to be page
    // aligned).
    //
    // The segment selector is VV << 8 because we don't need to shift
    // by a full 12 bits since the first 4 bits are the RPL and TI bits.
    //

    uint64_t vector_cs_selector =
        vmcs_n::exit_qualification::sipi::vector::get() << 8;

    uint64_t vector_cs_base =
        vmcs_n::exit_qualification::sipi::vector::get() << 12;

    vmcs_n::guest_cs_selector::set(vector_cs_selector);
    vmcs_n::guest_cs_base::set(vector_cs_base);
    vmcs_n::guest_cs_limit::set(0xFFFF);
    vmcs_n::guest_cs_access_rights::set(0x9B);

    vcpu->set_rip(0);

    vmcs_n::guest_activity_state::set(
        vmcs_n::guest_activity_state::active
    );

    // .........................................................................
    // Done
    // .........................................................................

    return true;
}

}
