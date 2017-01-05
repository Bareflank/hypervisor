//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#include <gsl/gsl>

#include <debug.h>
#include <constants.h>
#include <error_codes.h>
#include <guard_exceptions.h>
#include <memory_manager/memory_manager_x64.h>
#include <exit_handler/exit_handler_intel_x64.h>
#include <exit_handler/exit_handler_intel_x64_entry.h>
#include <exit_handler/exit_handler_intel_x64_support.h>

#include <intrinsics/pm_x64.h>
#include <intrinsics/cache_x64.h>
#include <intrinsics/cpuid_x64.h>
#include <intrinsics/vmx_intel_x64.h>

#include <vmcs/vmcs_intel_x64_32bit_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_32bit_read_only_data_fields.h>
#include <vmcs/vmcs_intel_x64_natural_width_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_natural_width_read_only_data_fields.h>
#include <vmcs/vmcs_intel_x64_64bit_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_check.h>
#include <vmcs/vmcs_intel_x64_debug.h>

using namespace x64;
using namespace intel_x64;

#include <mutex>
std::mutex g_unimplemented_handler_mutex;

exit_handler_intel_x64::exit_handler_intel_x64() :
    m_vmcs(nullptr),
    m_state_save(nullptr)
{ }

void
exit_handler_intel_x64::dispatch()
{ handle_exit(vmcs::exit_reason::basic_exit_reason::get()); }

void
exit_handler_intel_x64::halt() noexcept
{
    std::lock_guard<std::mutex> guard(g_unimplemented_handler_mutex);

    bferror << bfendl;
    bferror << bfendl;
    bferror << "Guest register state: " << bfendl;
    bferror << "----------------------------------------------------" << bfendl;
    bferror << "- m_state_save->rax: " << view_as_pointer(m_state_save->rax) << bfendl;
    bferror << "- m_state_save->rbx: " << view_as_pointer(m_state_save->rbx) << bfendl;
    bferror << "- m_state_save->rcx: " << view_as_pointer(m_state_save->rcx) << bfendl;
    bferror << "- m_state_save->rdx: " << view_as_pointer(m_state_save->rdx) << bfendl;
    bferror << "- m_state_save->rbp: " << view_as_pointer(m_state_save->rbp) << bfendl;
    bferror << "- m_state_save->rsi: " << view_as_pointer(m_state_save->rsi) << bfendl;
    bferror << "- m_state_save->rdi: " << view_as_pointer(m_state_save->rdi) << bfendl;
    bferror << "- m_state_save->r08: " << view_as_pointer(m_state_save->r08) << bfendl;
    bferror << "- m_state_save->r09: " << view_as_pointer(m_state_save->r09) << bfendl;
    bferror << "- m_state_save->r10: " << view_as_pointer(m_state_save->r10) << bfendl;
    bferror << "- m_state_save->r11: " << view_as_pointer(m_state_save->r11) << bfendl;
    bferror << "- m_state_save->r12: " << view_as_pointer(m_state_save->r12) << bfendl;
    bferror << "- m_state_save->r13: " << view_as_pointer(m_state_save->r13) << bfendl;
    bferror << "- m_state_save->r14: " << view_as_pointer(m_state_save->r14) << bfendl;
    bferror << "- m_state_save->r15: " << view_as_pointer(m_state_save->r15) << bfendl;
    bferror << "- m_state_save->rip: " << view_as_pointer(m_state_save->rip) << bfendl;
    bferror << "- m_state_save->rsp: " << view_as_pointer(m_state_save->rsp) << bfendl;

    bferror << bfendl;
    bferror << bfendl;
    bferror << "CPU Halted: " << bfendl;
    bferror << "----------------------------------------------------" << bfendl;
    bferror << "- vcpuid: " << m_state_save->vcpuid << bfendl;

    bferror << bfendl;
    bferror << bfendl;

    g_unimplemented_handler_mutex.unlock();

    pm::stop();
}

void
exit_handler_intel_x64::handle_exit(vmcs::value_type reason)
{
    switch (reason)
    {
        case vmcs::exit_reason::basic_exit_reason::cpuid:
            handle_cpuid();
            break;

        case vmcs::exit_reason::basic_exit_reason::invd:
            handle_invd();
            break;

        case vmcs::exit_reason::basic_exit_reason::vmcall:
            handle_vmcall();
            break;

        case vmcs::exit_reason::basic_exit_reason::vmxoff:
            handle_vmxoff();
            break;

        case vmcs::exit_reason::basic_exit_reason::rdmsr:
            handle_rdmsr();
            break;

        case vmcs::exit_reason::basic_exit_reason::wrmsr:
            handle_wrmsr();
            break;

        default:
            unimplemented_handler();
            break;
    };

    m_vmcs->resume();
}

void
exit_handler_intel_x64::handle_cpuid()
{
    auto ret = cpuid::get(m_state_save->rax,
                          m_state_save->rbx,
                          m_state_save->rcx,
                          m_state_save->rdx);

    m_state_save->rax = std::get<0>(ret);
    m_state_save->rbx = std::get<1>(ret);
    m_state_save->rcx = std::get<2>(ret);
    m_state_save->rdx = std::get<3>(ret);

    advance_rip();
}

void
exit_handler_intel_x64::handle_invd()
{
    cache::wbinvd();
    advance_rip();
}

void
exit_handler_intel_x64::handle_vmcall()
{
    auto &&regs = vmcall_registers_t{};

    switch (m_state_save->rax)
    {
        case VMCALL_EVENT:
            regs.r02 = m_state_save->rcx;
            break;

        default:
            regs.r02 = m_state_save->rcx;
            regs.r03 = m_state_save->rbx;
            regs.r04 = m_state_save->rsi;
            regs.r05 = m_state_save->r08;
            regs.r06 = m_state_save->r09;
            regs.r07 = m_state_save->r10;
            regs.r08 = m_state_save->r11;
            regs.r09 = m_state_save->r12;
            regs.r10 = m_state_save->r13;
            regs.r11 = m_state_save->r14;
            regs.r12 = m_state_save->r15;
            break;
    };

    if (m_state_save->rdx != VMCALL_MAGIC_NUMBER)
        return complete_vmcall(BF_VMCALL_FAILURE, regs);

    auto &&ret = guard_exceptions(BF_VMCALL_FAILURE, [&]
    {
        switch (m_state_save->rax)
        {
            case VMCALL_VERSIONS:
                handle_vmcall_versions(regs);
                break;

            case VMCALL_REGISTERS:
                handle_vmcall_registers(regs);
                break;

            case VMCALL_DATA:
                handle_vmcall_data(regs);
                break;

            case VMCALL_EVENT:
                handle_vmcall_event(regs);
                break;

            case VMCALL_UNITTEST:
                handle_vmcall_unittest(regs);
                break;

            default:
                throw std::runtime_error("unknown vmcall opcode");
        };
    });

    complete_vmcall(ret, regs);
}

void
exit_handler_intel_x64::complete_vmcall(
    ret_type ret, vmcall_registers_t &regs) noexcept
{
    switch (m_state_save->rax)
    {
        case VMCALL_EVENT:
            m_state_save->rcx = regs.r02;
            break;

        default:
            m_state_save->r15 = regs.r12;
            m_state_save->r14 = regs.r11;
            m_state_save->r13 = regs.r10;
            m_state_save->r12 = regs.r09;
            m_state_save->r11 = regs.r08;
            m_state_save->r10 = regs.r07;
            m_state_save->r09 = regs.r06;
            m_state_save->r08 = regs.r05;
            m_state_save->rsi = regs.r04;
            m_state_save->rbx = regs.r03;
            m_state_save->rcx = regs.r02;
            break;
    };

    m_state_save->rdx = static_cast < decltype(m_state_save->rdx) > (ret);
    advance_rip();
}

void
exit_handler_intel_x64::handle_vmxoff()
{ m_vmcs->promote(); }

void
exit_handler_intel_x64::handle_rdmsr()
{
    intel_x64::msrs::value_type msr = 0;

    switch (m_state_save->rcx)
    {
        case intel_x64::msrs::ia32_debugctl::addr:
            msr = vmcs::guest_ia32_debugctl::get();
            break;

        case x64::msrs::ia32_pat::addr:
            msr = vmcs::guest_ia32_pat::get();
            break;

        case intel_x64::msrs::ia32_efer::addr:
            msr = vmcs::guest_ia32_efer::get();
            break;

        case intel_x64::msrs::ia32_perf_global_ctrl::addr:
            msr = vmcs::guest_ia32_perf_global_ctrl::get();
            break;

        case intel_x64::msrs::ia32_sysenter_cs::addr:
            msr = vmcs::guest_ia32_sysenter_cs::get();
            break;

        case intel_x64::msrs::ia32_sysenter_esp::addr:
            msr = vmcs::guest_ia32_sysenter_esp::get();
            break;

        case intel_x64::msrs::ia32_sysenter_eip::addr:
            msr = vmcs::guest_ia32_sysenter_eip::get();
            break;

        case intel_x64::msrs::ia32_fs_base::addr:
            msr = vmcs::guest_fs_base::get();
            break;

        case intel_x64::msrs::ia32_gs_base::addr:
            msr = vmcs::guest_gs_base::get();
            break;

        default:
            msr = intel_x64::msrs::get(m_state_save->rcx);
            break;

        // QUIRK:
        //
        // The following is specifically for CPU-Z. For whatever reason, it is
        // reading the following undefined MSRs, which causes the system to
        // freeze since attempting to read these MSRs in the exit handler
        // will cause a GP which is not being caught. The result is, the core
        // that runs RDMSR on these freezes, the other cores receive an
        // INIT signal to reset, and the system dies.
        //

        case 0x31:
        case 0x39:
        case 0x1ae:
        case 0x1af:
        case 0x602:
            msr = 0;
            break;
    }

    m_state_save->rax = ((msr >> 0x00) & 0x00000000FFFFFFFF);
    m_state_save->rdx = ((msr >> 0x20) & 0x00000000FFFFFFFF);

    advance_rip();
}

void
exit_handler_intel_x64::handle_wrmsr()
{
    intel_x64::msrs::value_type msr = 0;

    msr |= ((m_state_save->rax & 0x00000000FFFFFFFF) << 0x00);
    msr |= ((m_state_save->rdx & 0x00000000FFFFFFFF) << 0x20);

    switch (m_state_save->rcx)
    {
        case intel_x64::msrs::ia32_debugctl::addr:
            vmcs::guest_ia32_debugctl::set(msr);
            break;

        case x64::msrs::ia32_pat::addr:
            vmcs::guest_ia32_pat::set(msr);
            break;

        case intel_x64::msrs::ia32_efer::addr:
            vmcs::guest_ia32_efer::set(msr);
            break;

        case intel_x64::msrs::ia32_perf_global_ctrl::addr:
            vmcs::guest_ia32_perf_global_ctrl::set(msr);
            break;

        case intel_x64::msrs::ia32_sysenter_cs::addr:
            vmcs::guest_ia32_sysenter_cs::set(msr);
            break;

        case intel_x64::msrs::ia32_sysenter_esp::addr:
            vmcs::guest_ia32_sysenter_esp::set(msr);
            break;

        case intel_x64::msrs::ia32_sysenter_eip::addr:
            vmcs::guest_ia32_sysenter_eip::set(msr);
            break;

        case intel_x64::msrs::ia32_fs_base::addr:
            vmcs::guest_fs_base::set(msr);
            break;

        case intel_x64::msrs::ia32_gs_base::addr:
            vmcs::guest_gs_base::set(msr);
            break;

        default:
            intel_x64::msrs::set(m_state_save->rcx, msr);
            break;
    }

    advance_rip();
}

void
exit_handler_intel_x64::advance_rip() noexcept
{ m_state_save->rip += vmcs::vm_exit_instruction_length::get(); }

void
exit_handler_intel_x64::unimplemented_handler() noexcept
{
    std::lock_guard<std::mutex> guard(g_unimplemented_handler_mutex);

    bferror << bfendl;
    bferror << bfendl;
    bferror << "Unimplemented Exit Handler: " << bfendl;
    bferror << "----------------------------------------------------" << bfendl;
    bferror << "- exit reason: "
            << view_as_pointer(vmcs::exit_reason::get()) << bfendl;
    bferror << "- exit reason string: "
            << vmcs::exit_reason::basic_exit_reason::description() << bfendl;
    bferror << "- exit qualification: "
            << view_as_pointer(vmcs::exit_qualification::get()) << bfendl;
    bferror << "- exit interrupt information: "
            << view_as_pointer(vmcs::vm_exit_interruption_information::get()) << bfendl;
    bferror << "- instruction length: "
            << view_as_pointer(vmcs::vm_exit_instruction_length::get()) << bfendl;
    bferror << "- instruction information: "
            << view_as_pointer(vmcs::vm_exit_instruction_information::get()) << bfendl;
    bferror << "- guest linear address: "
            << view_as_pointer(vmcs::guest_linear_address::get()) << bfendl;
    bferror << "- guest physical address: "
            << view_as_pointer(vmcs::guest_physical_address::get()) << bfendl;

    if (vmcs::exit_reason::vm_entry_failure::is_enabled())
    {
        bferror << bfendl;
        bferror << "VM-entry failure detected!!!" << bfendl;
        bferror << bfendl;

        guard_exceptions([&]
        { vmcs::check::all(); });

        guard_exceptions([&]
        { vmcs::debug::dump(); });
    }

    g_unimplemented_handler_mutex.unlock();

    this->halt();
}

void
exit_handler_intel_x64::handle_vmcall_versions(vmcall_registers_t &regs)
{
    switch (regs.r02)
    {
        case VMCALL_VERSION_PROTOCOL:
            regs.r03 = VMCALL_VERSION;
            regs.r04 = 0;
            regs.r05 = 0;
            break;

        case VMCALL_VERSION_BAREFLANK:
            regs.r03 = BAREFLANK_VERSION_MAJOR;
            regs.r04 = BAREFLANK_VERSION_MINOR;
            regs.r05 = BAREFLANK_VERSION_PATCH;
            break;

        case VMCALL_VERSION_USER:
            regs.r03 = USER_VERSION_MAJOR;
            regs.r04 = USER_VERSION_MINOR;
            regs.r05 = USER_VERSION_PATCH;
            break;

        default:
            throw std::runtime_error("unknown vmcall version index");
    }
}

void
exit_handler_intel_x64::handle_vmcall_registers(vmcall_registers_t &regs)
{
    bfdebug << "vmcall registers:" << bfendl;
    bfdebug << "r02: " << view_as_pointer(regs.r02) << bfendl;
    bfdebug << "r03: " << view_as_pointer(regs.r03) << bfendl;
    bfdebug << "r04: " << view_as_pointer(regs.r04) << bfendl;
    bfdebug << "r05: " << view_as_pointer(regs.r05) << bfendl;
    bfdebug << "r06: " << view_as_pointer(regs.r06) << bfendl;
    bfdebug << "r07: " << view_as_pointer(regs.r07) << bfendl;
    bfdebug << "r08: " << view_as_pointer(regs.r08) << bfendl;
    bfdebug << "r09: " << view_as_pointer(regs.r09) << bfendl;
    bfdebug << "r10: " << view_as_pointer(regs.r10) << bfendl;
    bfdebug << "r11: " << view_as_pointer(regs.r11) << bfendl;
    bfdebug << "r12: " << view_as_pointer(regs.r12) << bfendl;
}

void
exit_handler_intel_x64::handle_vmcall_data(vmcall_registers_t &regs)
{
    expects(regs.r05 != 0);
    expects(regs.r08 != 0);
    expects(regs.r06 != 0);
    expects(regs.r09 != 0);
    expects(regs.r09 >= regs.r06);
    expects(regs.r06 <= VMCALL_IN_BUFFER_SIZE);
    expects(regs.r09 <= VMCALL_OUT_BUFFER_SIZE);

    auto &&imap = bfn::make_unique_map_x64<char>(regs.r05, vmcs::guest_cr3::get(), regs.r06, vmcs::guest_ia32_pat::get());
    auto &&omap = bfn::make_unique_map_x64<char>(regs.r08, vmcs::guest_cr3::get(), regs.r09, vmcs::guest_ia32_pat::get());

    switch (regs.r04)
    {
        case VMCALL_DATA_STRING_UNFORMATTED:
        {
            std::string ostr;
            handle_vmcall_data_string_unformatted(std::string(imap.get(), regs.r06), ostr);
            reply_with_string(regs, ostr, omap);
            break;
        }

        case VMCALL_DATA_STRING_JSON:
        {
            json ojson;
            handle_vmcall_data_string_json(json::parse(std::string(imap.get(), regs.r06)), ojson);
            reply_with_json(regs, ojson, omap);
            break;
        }

        case VMCALL_DATA_BINARY_UNFORMATTED:
        {
            handle_vmcall_data_binary_unformatted(imap, omap);
            regs.r07 = VMCALL_DATA_BINARY_UNFORMATTED;
            regs.r09 = regs.r06;
            break;
        }

        default:
            throw std::runtime_error("unknown vmcall data type");
    }
}

void
exit_handler_intel_x64::handle_vmcall_event(vmcall_registers_t &regs)
{
    bfdebug << "vmcall event:" << bfendl;
    bfdebug << "r02: " << view_as_pointer(regs.r02) << bfendl;
}

void
exit_handler_intel_x64::handle_vmcall_data_string_unformatted(
    const std::string &istr, std::string &ostr)
{
    bfdebug << "received in vmm: " << istr << bfendl;
    ostr = istr;
}

void
exit_handler_intel_x64::handle_vmcall_data_string_json(
    const json &ijson, json &ojson)
{
    bfdebug << "received in vmm: " << ijson << bfendl;
    ojson = ijson;
}

void
exit_handler_intel_x64::handle_vmcall_data_binary_unformatted(
    const bfn::unique_map_ptr_x64<char> &imap,
    const bfn::unique_map_ptr_x64<char> &omap)
{
    bfdebug << "received binary data" << bfendl;
    __builtin_memcpy(omap.get(), imap.get(), imap.size());
}

void exit_handler_intel_x64::reply_with_string(
    vmcall_registers_t &regs, const std::string &str,
    const bfn::unique_map_ptr_x64<char> &omap)
{
    auto &&len = str.length();

    __builtin_memcpy(omap.get(), str.data(), len);

    regs.r07 = VMCALL_DATA_STRING_UNFORMATTED;
    regs.r09 = len;
}

void
exit_handler_intel_x64::reply_with_json(
    vmcall_registers_t &regs, const json &str,
    const bfn::unique_map_ptr_x64<char> &omap)
{
    auto &&dmp = str.dump();
    auto &&len = dmp.length();

    __builtin_memcpy(omap.get(), dmp.data(), len);

    regs.r07 = VMCALL_DATA_STRING_JSON;
    regs.r09 = len;
}
