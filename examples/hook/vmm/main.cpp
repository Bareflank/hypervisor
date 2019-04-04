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

#include <vmm.h>

ept::mmap g_guest_map{};
ept::mmap::entry_type g_guest_pte_shadow{};

/// Per-vCPU Data
///
/// This struct stores data that is used by each vCPU. There are really two
/// ways that you can handle user data that needs to be stored in a vCPU.
/// You can either subclass the vCPU and create your own vCPU factory to
/// return your version of the vCPU, or you can use the set_data(), data()
/// functions (which we do in this example) to store your own vCPU data.
///
struct d_t {

    // The following stores the:
    // - Guest virtual address of the hello_world() function
    // - Guest physical address of the hello_world() function
    // - Guest virtual address of the hooked_hello_world() function
    //
    uintptr_t m_hello_world_gva{};
    uintptr_t m_hello_world_gpa{};
    uintptr_t m_hooked_hello_world_gva{};

    // The following stores the page table entry (PTE) that represents the
    // guest physical address of the hello_world() function. We will flip
    // the "execute access" bit in this PTE to control access to the
    // hello_world() function
    //
    // Note that we use a reference_wrapper instead of a pointer to prevent
    // the possibility of accidentally dereferencing a nullptr.
    //
    std::reference_wrapper<ept::mmap::entry_type> m_pte{g_guest_pte_shadow};
};

void
global_init()
{
    bfdebug_info(0, "running hook example");
    bfdebug_lnbr(0);

    // Setup EPT. This will create our EPT memory map for the host OS. Note
    // that we use the identity_map() function as this ensures the MTRRs
    // are respected, and we map memory up to MAX_PHYS_ADDR which can be
    // changed if you system has a ton of extra physical memory. You could
    // also use the max physical memory returned by CPUID, or use the MTRRs
    // to determine the end of physical memory.
    //
    ept::identity_map(
        g_guest_map, MAX_PHYS_ADDR
    );
}

void vmcall_handler_hook(vcpu_t *vcpu);
void vmcall_handler_unhook(vcpu_t *vcpu);

bool
vmcall_handler(vcpu_t *vcpu)
{
    // If a VMCall is made, we either need to install our hook, or we
    // need to turn it off (uninstall it).
    //
    // Note that we use guard_exceptions() which will prevent an exception
    // from crashing the hypervisor. Instead, the exception will be
    // sent to the serial device, and the vmcall will return safely.
    //
    guard_exceptions([&] {
        switch (vcpu->rax())
        {
            case 0:
                vmcall_handler_hook(vcpu);
                break;

            default:
                vmcall_handler_unhook(vcpu);
                break;
        };
    });

    // Make sure we advance the instruction pointer. Otherwise, the VMCall
    // instruction will be executed in an infinite look. Also note that
    // the advance() function always returns true, which tells the base
    // hypervisor that this VM exit was successfully handled.
    //
    return vcpu->advance();
}

void
vmcall_handler_hook(vcpu_t *vcpu)
{
    // Get a reference to our per-vcpu data. Note that we need to explicitly
    // ask for a reference, similar to the std::any APIs.
    //
    auto &d = vcpu->data<d_t &>();

    // Store the guest virtual address of both the hello_world() function
    // and the hooked_hello_world() function
    //
    d.m_hello_world_gva = vcpu->rbx();
    d.m_hooked_hello_world_gva = vcpu->rcx();

    // The virtual address of the hello_world() function is a guest virtual
    // address. We need to use the guest's CR3 to figure out what the
    // guest's physical address of this virtual address is. The following
    // performs this conversion by parsing the guest's pages tables to
    // get the guest physical address, and since either EPT is not used
    // or it is a 1:1 map, the guest physical address == the host physical
    // address all the time so we can use the gpa as an hpa as needed.
    //
    auto [hpa, ignored1] = vcpu->gva_to_hpa(d.m_hello_world_gva);

    d.m_hello_world_gpa = hpa;
    bfignored(ignored1);

    // Now that we know what the physical address of the hello_world()
    // function is, we need to get the EPT PTE associated with this physical
    // address. The problem is, EPT was set up using 2M pages, which is
    // large. On x86_64, this would basically cause us to trap on every
    // single memory access of the entire userspace application (as
    // applications in 64bit are setup with 2M pages, typically). The
    // following converts our 2M page into 4K pages so that we can get
    // the PTE of just the 4k page that has our hello_world() application.
    //
    ept::identity_map_convert_2m_to_4k(
        g_guest_map,
        bfn::upper(d.m_hello_world_gpa, ::intel_x64::ept::pd::from)
    );

    // Get the 4k PTE associated with our hello_world() application
    //
    auto [pte, ignored2] = g_guest_map.entry(d.m_hello_world_gpa);

    d.m_pte = pte;
    bfignored(ignored2);

    // Disable execute access for the page associated with our
    // hello_world() application. Any attempt to
    // execute code on this page will generate an EPT violation which
    // will present us with an opportunity to hook the hello_world()
    // function
    //
    ::intel_x64::ept::pt::entry::execute_access::disable(d.m_pte);

    // Tell the VMCS to use our new EPT map
    //
    vcpu->set_eptp(g_guest_map);
}

bool
ept_execute_violation_handler(
    vcpu_t *vcpu, ept_violation_handler::info_t &info)
{
    bfignored(info);

    // Get a reference to our per-vcpu data. Note that we need to explicitly
    // ask for a reference, similar to the std::any APIs.
    //
    auto &d = vcpu->data<d_t &>();

    // If we got an EPT violation (i.e. this function was executed), it
    // means that our userspace application attempted to execute code in
    // the page that has our hello_world() function. 4k bytes worth of code
    // is sitting in this page, so we first need to check if the execute
    // access was actually the hello_world() function, or something else.
    // If this was our hello_world() function, we need to change the
    // guest's instruction pointer towards our hooked_hello_world() function
    // instead
    //
    if (vcpu->rip() == d.m_hello_world_gva) {
        vcpu->set_rip(d.m_hooked_hello_world_gva);
    }

    // Before we finish, we need to reenable execute access, otherwise
    // when this function finishes, an EPT violation will occur again.
    // The problem is, once we enable access to this page, we will stop
    // generating EPT violations, which will prevent us from installing
    // our hook if needed. To solve this, we single step the memory access
    // so that once it is done executing, we can disable execute access to
    // the page again. We do this by turning on the monitor trap flag.
    //
    vcpu->enable_monitor_trap_flag();
    ::intel_x64::ept::pt::entry::execute_access::enable(d.m_pte);

    // Return true, telling the base hypervisor that we have handled the
    // VM exit. Note that since this is an EPT violation, we do not
    // flush the TLB as the hardware will do this for us.
    //
    return true;
}

bool
mt_handler(vcpu_t *vcpu)
{
    // Get a reference to our per-vcpu data. Note that we need to explicitly
    // ask for a reference, similar to the std::any APIs.
    //
    auto &d = vcpu->data<d_t &>();

    // If this function is executed, it means that our memory access has
    // successfully executed, and we need to disable access to our page
    // so that we can continue to trap on execute accesses to it.
    //
    ::intel_x64::ept::pt::entry::execute_access::disable(d.m_pte);
    ::intel_x64::vmx::invept_global();

    // Return true, telling the base hypervisor that we have handled the
    // VM exit.
    //
    return true;
}

void
vmcall_handler_unhook(vcpu_t *vcpu)
{
    // Get a reference to our per-vcpu data. Note that we need to explicitly
    // ask for a reference, similar to the std::any APIs.
    //
    auto &d = vcpu->data<d_t &>();

    // Set our pte to our shadow. This effectively unhooks the pte while
    // ensuring that we are not setting the pte to a nullptr, which could
    // result in a crash if we did something wrong in this code.
    //
    d.m_pte = g_guest_pte_shadow;

    // To uninstall our hook, we need to convert our 4k pages back to a
    // single 2M page. This will ensure that the next time our userspace
    // application is executed, we can repeat our hook process over, and
    // over, and over without our EPT map getting distorted over time.
    //
    ept::identity_map_convert_4k_to_2m(
        g_guest_map,
        bfn::upper(d.m_hello_world_gpa, ::intel_x64::ept::pd::from)
    );

    // Clear our saved addresses as they are no longer valid.
    //
    d.m_hello_world_gva = {};
    d.m_hello_world_gpa = {};
    d.m_hooked_hello_world_gva = {};

    // Disable EPT as we no longer need it.
    //
    vcpu->disable_ept();
}

void
vcpu_init_nonroot(vcpu_t *vcpu)
{
    using namespace vmcs_n;
    using eptv_delegate_t = ept_violation_handler::handler_delegate_t;

    // Initialize our per-vcpu data.
    //
    vcpu->set_data<d_t>({});

    // Add a VMCall handler. This will catch the VMCalls made by the
    // userspace application and call the vmcall_handler() function.
    //
    vcpu->add_exit_handler_for_reason(
        exit_reason::basic_exit_reason::vmcall, vmcall_handler);

    // Add a Monitor Trap handler. This will catch Monitor Trap VM exits
    // and call the mt_handler() function. We will use the
    // monitor trap flag to single step attempts to execute code that
    // exists in the same physical page as our hello_world() function.
    //
    vcpu->add_monitor_trap_handler(mt_handler);

    // Add an EPT violation handler (for execute access). If an EPT
    // violation is made for execute accesses,  ept_execute_violation_handler()
    // will be called which is where we will perform our hook.
    //
    vcpu->add_ept_execute_violation_handler(ept_execute_violation_handler);
}

// Expected Output (make dump)
//
// [0x0] DEBUG: running hook example
// [0x0] DEBUG:
// [0x0] DEBUG: host os is now in a vm
// ...

// Expected Output (./prefixes/x86_64-userspace-elf/bin/hook)
//
// hello world
// hello world
// hooked hello world
// hooked hello world
// hello world
// hello world
