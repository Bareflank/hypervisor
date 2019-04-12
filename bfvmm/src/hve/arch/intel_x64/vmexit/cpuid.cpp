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

namespace bfvmm::intel_x64::vmexit
{

static bool
handle_cpuid_feature_information(vcpu *vcpu)
{
    using namespace ::intel_x64::cpuid;

    vcpu->set_rcx(
        clear_bit(vcpu->rcx(), feature_information::ecx::vmx::from)
    );

    return false;
}

static bool
handle_cpuid_0x4BF00000(vcpu *vcpu)
{
    vcpu->set_rax(0x4BF00001);
    vcpu->set_rbx(0);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    return vcpu->advance();
}

static bool
handle_cpuid_0x4BF00010(vcpu *vcpu)
{
    vcpu->set_rax(0);
    vcpu->set_rbx(0);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    vcpu_init_root(static_cast<vcpu_t *>(vcpu));
    return vcpu->advance();
}

static bool
handle_cpuid_0x4BF00011(vcpu *vcpu)
{
    vcpu->set_rax(0);
    vcpu->set_rbx(0);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    bfdebug_info(0, "host os is" bfcolor_green " now " bfcolor_end "in a vm");
    return vcpu->advance();
}

static bool
handle_cpuid_0x4BF00020(vcpu *vcpu)
{
    vcpu->set_rax(0);
    vcpu->set_rbx(0);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    vcpu_fini_root(static_cast<vcpu_t *>(vcpu));
    return vcpu->advance();
}

static bool
handle_cpuid_0x4BF00021(vcpu *vcpu)
{
    vcpu->set_rax(0);
    vcpu->set_rbx(0);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    bfdebug_info(0, "host os is" bfcolor_red " not " bfcolor_end "in a vm");
    vcpu->promote();

    throw std::runtime_error("unreachable exception");
}

cpuid::cpuid(
    gsl::not_null<vcpu *> vcpu)
{
    vcpu->add_handler(
        vmcs_n::exit_reason::basic_exit_reason::cpuid,
        handler_delegate_t::create<cpuid, &cpuid::handle>(this)
    );

    this->add_handler(
        ::intel_x64::cpuid::feature_information::addr,
        handler_delegate_t::create<handle_cpuid_feature_information>()
    );

    this->add_emulator(
        0x4BF00000, handler_delegate_t::create<handle_cpuid_0x4BF00000>()
    );

    this->add_emulator(
        0x4BF00010, handler_delegate_t::create<handle_cpuid_0x4BF00010>()
    );

    this->add_emulator(
        0x4BF00020, handler_delegate_t::create<handle_cpuid_0x4BF00020>()
    );

    if (vcpu->is_guest_vm_vcpu()) {
        return;
    }

    this->add_emulator(
        0x4BF00011, handler_delegate_t::create<handle_cpuid_0x4BF00011>()
    );

    this->add_emulator(
        0x4BF00021, handler_delegate_t::create<handle_cpuid_0x4BF00021>()
    );
}

// -----------------------------------------------------------------------------
// Public APIs
// -----------------------------------------------------------------------------

void
cpuid::add_handler(
    cpuid_n::leaf_t leaf, const handler_delegate_t &d)
{ m_handlers[leaf].push_front(d); }

void
cpuid::add_emulator(
    cpuid_n::leaf_t leaf, const handler_delegate_t &d)
{ m_emulators[leaf].push_front(d); }

void
cpuid::execute(vcpu *vcpu) noexcept
{
    const auto [rax, rbx, rcx, rdx] =
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
execute_handlers(
    vcpu *vcpu, const std::list<handler_delegate_t> &handlers)
{
    for (const auto &d : handlers) {
        if (d(vcpu)) {
            return true;
        }
    }

    return vcpu->advance();
}

static bool
execute_emulators(
    vcpu *vcpu, const std::list<handler_delegate_t> &emulators)
{
    for (const auto &d : emulators) {
        if (d(vcpu)) {
            return true;
        }
    }

    return false;
}

bool
cpuid::handle(vcpu *vcpu)
{
    const auto &emulators =
        m_emulators.find(vcpu->rax());

    const auto ___ = gsl::finally([vcpu] {
        vcpu->set_gr1(0);
        vcpu->set_gr2(0);
    });

    vcpu->set_gr1(vcpu->rax());
    vcpu->set_gr2(vcpu->rcx());

    if (emulators != m_emulators.end()) {
        return execute_emulators(vcpu, emulators->second);
    }

    if (vcpu->is_guest_vm_vcpu()) {
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
