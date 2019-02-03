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

static bool
handle_cpuid_feature_information(
    vcpu *vcpu, cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    // Currently, we do not support nested virtualization. As a result,
    // the EAPIs adds a default handler to disable support for VMXE here.
    //

    info.rcx =
        clear_bit(
            info.rcx, ::intel_x64::cpuid::feature_information::ecx::vmx::from
        );

    return true;
}

static bool
handle_cpuid_0x4BF00000(
    vcpu *vcpu, cpuid_handler::info_t &info)
{
    /// Ack
    ///
    /// This can be used by an application to ack the existence of the
    /// hypervisor. This is useful because vmcall only exists if the hypervisor
    /// is running while cpuid can be run from any ring, and always exists
    /// which means it can be used to ack safely from any application.
    ///

    info.rax = 0x4BF00001;
    return true;
}

static bool
handle_cpuid_0x4BF00011(
    vcpu *vcpu, cpuid_handler::info_t &info)
{
    /// Say Hi
    ///
    /// If the vCPU is a host vCPU and not a guest vCPU, we should say hi
    /// so that the user of Bareflank has a simple, reliable way to know
    /// that the hypervisor is running.
    ///

    bfdebug_info(0, "host os is" bfcolor_green " now " bfcolor_end "in a vm");
    return true;
}

static bool
handle_cpuid_0x4BF00021(
    vcpu *vcpu, cpuid_handler::info_t &info)
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

    // Unreachable
    return true;
}

cpuid_handler::cpuid_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_handler(
        exit_reason::basic_exit_reason::cpuid,
        ::handler_delegate_t::create<cpuid_handler, &cpuid_handler::handle>(this)
    );

    this->add_handler(
        ::intel_x64::cpuid::feature_information::addr,
        cpuid_handler_delegate_t::create<handle_cpuid_feature_information>()
    );

    this->add_handler(
        0x4BF00000,
        cpuid_handler_delegate_t::create<handle_cpuid_0x4BF00000>()
    );

    this->add_handler(
        0x4BF00011,
        cpuid_handler_delegate_t::create<handle_cpuid_0x4BF00011>()
    );

    this->add_handler(
        0x4BF00021,
        cpuid_handler_delegate_t::create<handle_cpuid_0x4BF00021>()
    );
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
cpuid_handler::add_handler(
    leaf_t leaf, const handler_delegate_t &d)
{ m_handlers[leaf].push_front(d); }

void
cpuid_handler::emulate(leaf_t leaf)
{ m_emulate[leaf] = true; }

void
cpuid_handler::set_default_handler(
    const ::handler_delegate_t &d)
{ m_default_handler = d; }

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
cpuid_handler::handle(vcpu *vcpu)
{
    auto user_already_emulating = m_emulate[vcpu->rax()];

    const auto &hdlrs =
        m_handlers.find(vcpu->rax());

    if (hdlrs != m_handlers.end()) {

        struct info_t info = {
            0, 0, 0, 0, false, false
        };

        if (!user_already_emulating) {
            auto [rax, rbx, rcx, rdx] =
                ::x64::cpuid::get(
                    gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rax()),
                    gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rbx()),
                    gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rcx()),
                    gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rdx())
                );

            info.rax = rax;
            info.rbx = rbx;
            info.rcx = rcx;
            info.rdx = rdx;
        }

        for (const auto &d : hdlrs->second) {
            if (d(vcpu, info)) {

                if (!info.ignore_write) {
                    vcpu->set_rax(info.rax);
                    vcpu->set_rbx(info.rbx);
                    vcpu->set_rcx(info.rcx);
                    vcpu->set_rdx(info.rdx);
                }

                if (!info.ignore_advance) {
                    return vcpu->advance();
                }

                return true;
            }
        }
    }

    if (m_default_handler.is_valid()) {
        return m_default_handler(vcpu);
    }

    if (user_already_emulating) {
        return false;
    }

    auto ret =
        ::x64::cpuid::get(
            gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rax()),
            gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rbx()),
            gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rcx()),
            gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rdx())
        );

    vcpu->set_rax(ret.rax);
    vcpu->set_rbx(ret.rbx);
    vcpu->set_rcx(ret.rcx);
    vcpu->set_rdx(ret.rdx);

    return vcpu->advance();
}

}
