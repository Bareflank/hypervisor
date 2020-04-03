#ifndef VMM_X64_HPP
#define VMM_X64_HPP

#include <vmm/vcpu/x64/x64_vcpu.hpp>
#include <vmm/vm/x64/x64_vm.hpp>
#include <bsl/delegate.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/exit_code.hpp>

namespace vmm
{

bsl::errc_type
root_vm_init(vmm::x64_vm &vm) noexcept;

x64_vm &
create_x64_vm(uint32_t n_vcpus) noexcept;

}

#endif
