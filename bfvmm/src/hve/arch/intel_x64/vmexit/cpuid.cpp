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

#include <bfexports.h>
#include <hve/arch/intel_x64/vcpu.h>

void
WEAK_SYM vcpu_init_root(vcpu_t *vcpu)
{ bfignored(vcpu); }

void
WEAK_SYM vcpu_fini_root(vcpu_t *vcpu)
{ bfignored(vcpu); }

namespace bfvmm::intel_x64
{

static bool
handle_cpuid_feature_information(vcpu *vcpu)
{
    using namespace ::intel_x64::cpuid;

    // Currently, we do not support nested virtualization. As a result,
    // the EAPIs adds a default handler to disable support for VMXE here.
    //

    vcpu->set_rcx(
        clear_bit(vcpu->rcx(), feature_information::ecx::vmx::from)
    );

    return false;
}

static bool
handle_cpuid_0x4BF00000(vcpu *vcpu)
{
    /// Ack
    ///
    /// This can be used by an application to ack the existence of the
    /// hypervisor. This is useful because vmcall only exists if the hypervisor
    /// is running while cpuid can be run from any ring, and always exists
    /// which means it can be used to ack safely from any application.
    ///

    vcpu->set_rax(0x4BF00001);
    return vcpu->advance();
}

static bool
handle_cpuid_0x4BF00010(vcpu *vcpu)
{
    /// Init
    ///
    /// Some initialization is required after the hypervisor has started. For
    /// example, any memory mapped resources such as ACPI or VT-d need to be
    /// initalized using the VMM's CR3, and not the hosts.
    ///

    vcpu_init_root(vcpu);
    return vcpu->advance();
}

static bool
handle_cpuid_0x4BF00011(vcpu *vcpu)
{
    /// Say Hi
    ///
    /// If the vCPU is a host vCPU and not a guest vCPU, we should say hi
    /// so that the user of Bareflank has a simple, reliable way to know
    /// that the hypervisor is running.
    ///

    bfdebug_info(0, "host os is" bfcolor_green " now " bfcolor_end "in a vm");
    return vcpu->advance();
}

static bool
handle_cpuid_0x4BF00020(vcpu *vcpu)
{
    /// Fini
    ///
    /// Some teardown logic is required before the hypervisor stops running.
    /// These handlers can be used in these scenarios.
    ///

    vcpu_fini_root(vcpu);
    return vcpu->advance();
}

static bool
handle_cpuid_0x4BF00021(vcpu *vcpu)
{
    /// Say Goobye
    ///
    /// The most reliable method for turning off the hypervisor is from the
    /// exit handler as it ensures that all of the destructors are executed
    /// after a promote, and not during. Also, say goodbye before we promote
    /// and turn off the hypervisor.
    ///

    bfdebug_info(0, "host os is" bfcolor_red " not " bfcolor_end "in a vm");
    vcpu->promote();

    throw std::runtime_error("unreachable exception");
}

cpuid_handler::cpuid_handler(
    gsl::not_null<vcpu *> vcpu)
{
    using namespace vmcs_n;

    vcpu->add_exit_handler_for_reason(
        exit_reason::basic_exit_reason::cpuid,
    {&cpuid_handler::handle, this}
    );

    this->add_handler(
        ::intel_x64::cpuid::feature_information::addr,
        handle_cpuid_feature_information
    );

    this->add_emulator(0x4BF00000, handle_cpuid_0x4BF00000);
    this->add_emulator(0x4BF00010, handle_cpuid_0x4BF00010);
    this->add_emulator(0x4BF00020, handle_cpuid_0x4BF00020);

    if (vcpu->is_guest_vcpu()) {
        return;
    }

    this->add_emulator(0x4BF00011, handle_cpuid_0x4BF00011);
    this->add_emulator(0x4BF00021, handle_cpuid_0x4BF00021);
}

// -----------------------------------------------------------------------------
// Public APIs
// -----------------------------------------------------------------------------

void
cpuid_handler::add_handler(
    leaf_t leaf, const handler_delegate_t &d)
{ m_handlers[leaf].push_front(d); }

void
cpuid_handler::add_emulator(
    leaf_t leaf, const handler_delegate_t &d)
{ m_emulators[leaf].push_front(d); }

void
cpuid_handler::execute(gsl::not_null<vcpu *> vcpu)
{
    vcpu->set_gr1(vcpu->rax());
    vcpu->set_gr2(vcpu->rcx());

    auto [rax, rbx, rcx, rdx] =
        ::x64::cpuid::get(
            gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rax()),
            gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rbx()),
            gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rcx()),
            gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rdx())
        );

    vcpu->set_rax(rax);
    vcpu->set_rbx(rbx);
    vcpu->set_rcx(rcx);
    vcpu->set_rdx(rdx);
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

static bool
execute_handlers(vcpu *vcpu, const std::list<handler_delegate_t> &handlers)
{
    for (const auto &d : handlers) {
        if (d(vcpu)) {
            return true;
        }
    }

    return vcpu->advance();
}

static bool
execute_emulators(vcpu *vcpu, const std::list<handler_delegate_t> &emulators)
{
    for (const auto &d : emulators) {
        if (d(vcpu)) {
            return true;
        }
    }

    return false;
}

bool
cpuid_handler::handle(vcpu *vcpu)
{
    const auto &emulators =
        m_emulators.find(vcpu->rax());

    if (emulators != m_emulators.end()) {
        return execute_emulators(vcpu, emulators->second);
    }

    if (m_whitelist) {
        vcpu->set_gr1(vcpu->rax());
        vcpu->set_gr2(vcpu->rcx());
        return false;
    }

    const auto &handlers =
        m_handlers.find(vcpu->rax());

    this->execute(vcpu);

    if (handlers != m_handlers.end()) {
        return execute_handlers(vcpu, handlers->second);
    }

    return vcpu->advance();
}

}
