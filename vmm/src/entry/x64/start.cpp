#include <bsl/exit_code.hpp>
#include <virtual_machine_monitor_instance.hpp>
#include <vmm/x64.hpp>

#include <vm/x64/x64_vm_seam.hpp>
#include <vm/vm_id_null.hpp>
#include <vm/x64/x64_vcpu_op.hpp>

#include <vcpu/x64/x64_vcpu_seam.hpp>
#include <vcpu/vcpu_property.hpp>
#include <vcpu/vcpu_virtual_register.hpp>
#include <vcpu/x64/intel/intel_execute.hpp>
#include <vcpu/x64/intel/intel_instruction_pointer.hpp>
#include <vcpu/x64/intel/intel_nested_paging.hpp>
#include <vcpu/x64/intel/intel_cpuid.hpp>
#include <vcpu/x64/intel/intel_cr0.hpp>
#include <vcpu/x64/intel/intel_cr3.hpp>
#include <vcpu/x64/intel/intel_cr4.hpp>
#include <vcpu/x64/intel/intel_external_interrupt.hpp>
#include <vcpu/x64/intel/intel_general_register_x64.hpp>
#include <vcpu/x64/intel/intel_init_signal.hpp>
#include <vcpu/x64/intel/intel_interrupt_window.hpp>
#include <vcpu/x64/intel/intel_io_port.hpp>
#include <vcpu/x64/intel/intel_monitor_trap.hpp>
#include <vcpu/x64/intel/intel_nmi.hpp>
#include <vcpu/x64/intel/intel_nmi_window.hpp>
#include <vcpu/x64/intel/intel_preemption_timer.hpp>
#include <vcpu/x64/intel/intel_rdmsr.hpp>
#include <vcpu/x64/intel/intel_sipi_signal.hpp>
#include <vcpu/x64/intel/intel_vmexit.hpp>
#include <vcpu/x64/intel/intel_vpid.hpp>
#include <vcpu/x64/intel/intel_wrmsr.hpp>
#include <vcpu/x64/intel/intel_xcr0.hpp>

namespace vmm
{
    typedef x64_vcpu_seam<
        // Generic vcpu implementations:
        intel_execute,
        intel_instruction_pointer,
        intel_nested_paging,
        vcpu_property,
        vcpu_virtual_register,
        // x64 vcpu implementations:
        intel_cpuid,
        intel_cr0,
        intel_cr3,
        intel_cr4,
        intel_external_interrupt,
        intel_general_register_x64,
        intel_init_signal,
        intel_interrupt_window,
        intel_io_port,
        intel_monitor_trap,
        intel_nmi,
        intel_nmi_window,
        intel_preemption_timer,
        intel_rdmsr,
        intel_sipi_signal,
        intel_vmexit,
        intel_vpid,
        intel_wrmsr,
        intel_xcr0
    > vcpu_type;

    typedef x64_vm_seam<
        vm_id_null,
        x64_vcpu_op
    > vm_type;

    static virtual_machine_monitor_instance<
        vm_type,
        vcpu_type
    > g_vmm{};

    x64_vm &
    create_x64_vm(uint32_t n_vcpus) noexcept
    { return g_vmm.make_virtual_machine(n_vcpus); }

    bsl::errc_type
    do_command_vmm_create(void * context)
    {
        auto n_physical_cpus = 4;   // <-- Get this in from *context
        x64_vm &root_vm = g_vmm.make_virtual_machine(n_physical_cpus);
        // TODO: Configure the root vm and root vcpus

        root_vm_init(root_vm);
        return bsl::exit_failure;
    }

    bsl::errc_type
    do_command_vmm_add_cpu(void * context)
    {
        x64_vcpu &root_vcpu = g_vmm.make_vcpu();
        // TODO: Configure the vcpu with any logic that makes it a "root" vcpu
        // TODO: Add the vcpu to the root domain
        return bsl::exit_failure;
    }

    bsl::errc_type
    do_command(uint32_t cmd, void * context)
    {
        switch(cmd) {
        case 1:
            do_command_vmm_create(context);
            break;
        case 2:
            do_command_vmm_add_cpu(context);
            break;
        default:
            break;
        };

        return bsl::exit_failure;
    }

}

extern "C"
bsl::exit_code
start(uint32_t cmd, void * context)
{
    vmm::do_command(1, context);
    return bsl::exit_failure;
}
