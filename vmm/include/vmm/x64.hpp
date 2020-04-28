#ifndef VMM_X64_HPP
#define VMM_X64_HPP

#include <vmm/platform/x64/x64_platform.hpp>
#include <vmm/vcpu/x64/x64_vcpu.hpp>
#include <vmm/vm/x64/x64_vm.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/exit_code.hpp>

namespace vmm
{

/// @brief The user-defined entry point into the Bareflank Hypervisor SDK.
///     This function gets called on the vmm's bootstrap cpu (i.e. the cpu that
///     initilizes the vmm first), and provides a way to configure additional
///     entry points for the given platform root virutal machine.
///
/// @param root_vm A virtual machine that represents the host system on which
///     the Bareflank Hypervisor SDK was loaded.
/// @param platform A platform object that represents the host system on which
///     the Bareflank Hypervisor SDK was loaded.
///
/// @return User returns 0 to indicate success, all other values indicate
///     failure
bsl::errc_type init_vmm(x64_vm &root_vm, x64_platform &platform) noexcept;

/// @brief Create a x64 based virtual machine, with the given number of vcpus
///
/// @param n_vpus The number of vcpus to be given to the virtual machine
///
/// @return An x64_vm instance
x64_vm & create_x64_vm(uint32_t n_vcpus) noexcept;

}

#endif
