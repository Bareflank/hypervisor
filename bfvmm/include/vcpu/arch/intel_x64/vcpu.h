//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

#ifndef VCPU_INTEL_X64_H
#define VCPU_INTEL_X64_H

#include "../../vcpu.h"
#include "../../../hve/arch/intel_x64/vmxon/vmxon.h"
#include "../../../hve/arch/intel_x64/vmcs/vmcs.h"
#include "../../../hve/arch/intel_x64/vmcs/vmcs_state_vmm.h"
#include "../../../hve/arch/intel_x64/vmcs/vmcs_state_hvm.h"
#include "../../../hve/arch/intel_x64/exit_handler/exit_handler.h"

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_VCPU
#ifdef SHARED_VCPU
#define EXPORT_VCPU EXPORT_SYM
#else
#define EXPORT_VCPU IMPORT_SYM
#endif
#else
#define EXPORT_VCPU
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm
{
namespace intel_x64
{

/// Virtual CPU (Intel x86_64)
///
/// The Virtual CPU represents a "CPU" to the hypervisor that is specific to
/// Intel x86_64.
///
/// This Intel specific vCPU class provides all of the functionality of the
/// base vCPU, but also adds classes specific to Intel's VT-x including the
/// vmxon, vmcs, exit_handler and
/// intrinsics classes.
///
/// Note that these should not be created directly, but instead should be
/// created by the vcpu_manager, which uses the vcpu_factory to actually
/// create a vcpu.
///
class EXPORT_VCPU vcpu : public bfvmm::vcpu
{
public:

    /// Constructor
    ///
    /// Creates a vCPU with the provided resources. This constructor
    /// provides a means to override and repalce the internal resources of the
    /// vCPU. Note that if one of the resources is set to NULL, a default
    /// will be constructed in its place, providing a means to select which
    /// internal components to override.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param id the id of the vcpu
    /// @param vmxon the vmxon the vcpu should use. If you
    ///     provide nullptr, a default vmxon will be created.
    /// @param vmcs the vmcs the vcpu should use. If you
    ///     provide nullptr, a default vmcs will be created.
    /// @param exit_handler the exit handler the vcpu should use. If you
    ///     provide nullptr, a default exit handler will be created.
    /// @param vmm_state the vmm state the vcpu should use. If you
    ///     provide nullptr, a default vmm state will be created.
    /// @param guest_state the guest state the vcpu should use. If you
    ///     provide nullptr, a default guest state will be created.
    ///
    vcpu(
        vcpuid::type id,
        std::unique_ptr<vmxon> vmxon = nullptr,
        std::unique_ptr<vmcs> vmcs = nullptr,
        std::unique_ptr<exit_handler> exit_handler = nullptr,
        std::unique_ptr<vmcs_state> vmm_state = nullptr,
        std::unique_ptr<vmcs_state> guest_state = nullptr);

    /// Destructor
    ///
    ~vcpu() override = default;

    /// Init vCPU
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    void init(user_data *data = nullptr) override;

    /// Fini vCPU
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    void fini(user_data *data = nullptr) override;

    /// Run vCPU
    ///
    /// @expects this->is_initialized() == true
    /// @ensures none
    ///
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    void run(user_data *data = nullptr) override;

    /// Halt vCPU
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    void hlt(user_data *data = nullptr) override;

private:

    bool m_vmcs_launched{false};

protected:

    /// @cond

    std::unique_ptr<vmxon> m_vmxon;
    std::unique_ptr<vmcs> m_vmcs;
    std::unique_ptr<exit_handler> m_exit_handler;
    std::unique_ptr<state_save> m_state_save;
    std::unique_ptr<vmcs_state> m_vmm_state;
    std::unique_ptr<vmcs_state> m_guest_state;

    /// @endcond

public:

    /// @cond

    vcpu(vcpu &&) noexcept = default;
    vcpu &operator=(vcpu &&) noexcept = default;

    vcpu(const vcpu &) = delete;
    vcpu &operator=(const vcpu &) = delete;

    /// @endcond
};

}
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
