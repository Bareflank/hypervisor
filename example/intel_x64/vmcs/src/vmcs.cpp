#include <vmm/x64.hpp>
#include <pal/vmcs/eptp.h>
#include <pal/vmcs/exit_reason.h>

namespace vmm
{

void root_vcpu_init(x64_vcpu &vcpu) noexcept
{
    // You can interact with the VMCS associated with this function's given vcpu
    // through the Bareflank Processor Abstraction Layer (PAL). The PAL has
    // accessor functions (get/set) for VMCS registers, and fields within those
    // registers. For example:
    auto eptp = pal::eptp::get();
    auto ept_levels = pal::eptp::ept_page_walk_length::get();

    // You can read and write directly to a VMCS field:
    pal::eptp::ept_pml4_table::set(0xDEADBEEF);
    auto pml4 = pal::eptp::ept_pml4_table::get();

    // Or you can read and write using intermediate integer values:
    auto reason = pal::exit_reason::get();
    auto basic_reason = pal::exit_reason::basic_exit_reason::get(reason);
    auto vmentry_failure = pal::exit_reason::vm_entry_failure::is_enabled(reason);

    return;
}

bsl::errc_type vmm_init(x64_vm &root_vm, x64_platform &platform) noexcept
{
    root_vm.vcpu_init_handler_set(root_vcpu_init);
    return 0;
}

}
