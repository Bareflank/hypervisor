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

#ifndef VCPU_H
#define VCPU_H

#include <list>
#include <string>
#include <memory>

#include <bfgsl.h>
#include <bftypes.h>
#include <bfvcpuid.h>
#include <bfobject.h>
#include <bfdelegate.h>

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

/// Virtual CPU
///
/// The vCPU represents a "core" for a machine.
///
/// For the host VM (the VM that starts the hypervisor), 1 vCPU must exist
/// for each physical core. These vCPUs are special. Their IDs are their
/// physical core nums as assigned by the host OS. This is because the "guest"
/// part of the ID is 0. The resources these vCPUs are given should match
/// the resources the host OS is using. Whether this is a type 1 or type 2
/// configuration, the host OS is usually the OS that is already running when
/// the hypervisor is loaded. In a type 1 configuration, this is UEFI, which
/// will later boot another OS (e.g. Windows, Linux or macOS) after the
/// hypervisor is loaded. In a type 2 configuration, the host OS is the
/// OS that is already running. Keep in mind that this is typically how it's
/// done, but doesn't have to be the case. For example, in an embedded case,
/// it might make sense to start from UEFI, and boot a separate control and
/// hardware VM and never execute the UEFI instance ever again. Just
/// depends on what your looking for. The goal here is to create a vCPU
/// architecture that can support any configuration your looking for.
///
/// For a guest VM, there can be any number of vCPUs. The first half of the
/// ID is the guest ID, and the second half of the ID is a unique identifier.
/// The goal with Bareflank is to allow any number of cores, regardless
/// of the physical core configuration. To support this, vCPUs
/// can be scheduled on any core, and the ID does not correlate with
/// a physical core. It's up to the vCPU implementation to figure out how to
/// schedule a core on the proper vCPU.
///
/// This generic vCPU class not only provides the base class that architecture
/// specific vCPUs will be created from, but it also provides some of the base
/// functionality that is common between all vCPUs.
///
/// The init, fini, run and hlt functions must be executed in the proper
/// order. Each vCPU must be initialized and finalized. The destructor for
/// the vCPU should not be used as destructors are labeled "noexcept" by
/// default. Instead the init and fini functions act as constructors /
/// destructors that can handle errors if they should arise.
///
/// Note that these should not be created directly, but instead should be
/// created by the vcpu_manager, which uses the vcpu_factory to actually
/// create a vcpu. The vcpu_factory is provided by default, but should be
/// overloaded by a Bareflank extension to provide custom logic on how to
/// implement the hypervisor itself. It's in this function, that host-only,
/// type 1 and type 2 hypervisors can be defined (including guest support).
/// Also note that the vCPU is a base class. The vcpu_factory really should
/// be creating architectural vCPUs as this class doesn't do much.
///
class EXPORT_VCPU vcpu
{
public:

    using run_delegate_t = delegate<void(bfobject *)>;      ///< Run delegate type
    using hlt_delegate_t = delegate<void(bfobject *)>;      ///< Halt delegate type
    using init_delegate_t = delegate<void(bfobject *)>;     ///< Init delegate type
    using fini_delegate_t = delegate<void(bfobject *)>;     ///< Fini delegate type

    /// Constructor
    ///
    /// Creates a vCPU with the provided id. This constructor
    /// provides a means to override and replace the internal resources of the
    /// vCPU. Note that if one of the resources is set to nullptr, a default
    /// will be constructed in its place, providing a means to select which
    /// internal components to override.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param id the id of the vcpu
    ///
    vcpu(vcpuid::type id);

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual ~vcpu() = default;

    /// Run
    ///
    /// Executes the vCPU. The vCPU can be in two different states prior to
    /// executing this function. When the vCPU is first created, the run
    /// function "starts" the vCPU's execution from a default state. If the
    /// vCPU was halted, running the vCPU again "resumes" its execution.
    /// When a VM exit occurs, the exit handler might be asked by the control
    /// VM to schedule a different vCPU. When this happens, it will likely
    /// call this function.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param obj object that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    VIRTUAL void run(bfobject *obj = nullptr);

    /// Halt
    ///
    /// Halts the vCPU. The process of "pausing" a vCPU occurs when a VM exit
    /// occurs, and the VM's state is saved. VM exits could occur for many
    /// reasons including an instruction needs to be emulated (e.g. cpuid),
    /// an interrupt has fired (e.g. the periodic interrupt), or the hlt
    /// instruction has executed (e.g. the OS running on the vCPU has gone
    /// into idle).
    ///
    /// Since a VM exit pauses the vCPU, this function is designed to tear
    /// down the vCPU. In some cases this is not needed as deleting the
    /// vCPU's resources is enough, but in other cases, special actions must
    /// be taken on a complete tear down. A good example of this is the
    /// host-only case. On tear down, the VMM needs to promote the host OS
    /// back to root operation prior to disabling the hypervisor completely.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param obj object that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    VIRTUAL void hlt(bfobject *obj = nullptr);

    /// Init vCPU
    ///
    /// Initializes the vCPU. This function should only be run once. To
    /// re-execute this function, fini should be used first. Both init
    /// and fini are used in place of the constructor / destructor for some
    /// logic that certainly could generate an exception.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param obj object that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    VIRTUAL void init(bfobject *obj = nullptr);

    /// Fini vCPU
    ///
    /// Finalizes the vCPU. This function should only be run once. To
    /// re-execute this function, init should be used first. Both init
    /// and fini are used in place of the constructor / destructor for some
    /// logic that certainly could generate an exception.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param obj object that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    VIRTUAL void fini(bfobject *obj = nullptr);

    /// vCPU Id
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return the vCPU's id
    ///
    VIRTUAL vcpuid::type id() const
    { return m_id; }

    /// Is Running
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if the vCPU is running, false otherwise.
    ///
    VIRTUAL bool is_running()
    { return m_is_running; }

    /// Is Initialized
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if the vCPU is initialized, false otherwise.
    ///
    VIRTUAL bool is_initialized()
    { return m_is_initialized; }

    /// Is Bootstrap vCPU
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if this vCPU is the bootstrap vCPU, false otherwise
    ///
    VIRTUAL bool is_bootstrap_vcpu()
    { return vcpuid::is_bootstrap_vcpu(m_id); }

    /// Is Host VM vCPU
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if this vCPU belongs to the host VM, false otherwise
    ///
    VIRTUAL bool is_host_vm_vcpu()
    { return vcpuid::is_hvm_vcpu(m_id); }

    /// Add Run Delegate
    ///
    /// Adds a run delegate to the VCPU. The delegates are added to a queue and
    /// executed in FIFO order. All delegates are executed unless an exception
    /// is thrown that is not handled.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param d the delegate to add to the vcpu
    ///
    VIRTUAL void add_run_delegate(run_delegate_t &&d) noexcept
    { m_run_delegates.push_front(std::move(d)); }

    /// Add Halt Delegate
    ///
    /// Adds a halt delegate to the VCPU. The delegates are added to a queue and
    /// executed in FIFO order. All delegates are executed unless an exception
    /// is thrown that is not handled.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param d the delegate to add to the vcpu
    ///
    VIRTUAL void add_hlt_delegate(hlt_delegate_t &&d) noexcept
    { m_hlt_delegates.push_front(std::move(d)); }

    /// Add Init Delegate
    ///
    /// Adds a init delegate to the VCPU. The delegates are added to a queue and
    /// executed in FIFO order. All delegates are executed unless an exception
    /// is thrown that is not handled.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param d the delegate to add to the vcpu
    ///
    VIRTUAL void add_init_delegate(init_delegate_t &&d) noexcept
    { m_init_delegates.push_front(std::move(d)); }

    /// Add Fini Delegate
    ///
    /// Adds a fini delegate to the VCPU. The delegates are added to a queue and
    /// executed in FIFO order. All delegates are executed unless an exception
    /// is thrown that is not handled.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param d the delegate to add to the vcpu
    ///
    VIRTUAL void add_fini_delegate(fini_delegate_t &&d) noexcept
    { m_fini_delegates.push_front(std::move(d)); }

private:

    vcpuid::type m_id;

    bool m_is_running{false};
    bool m_is_initialized{false};

    std::list<run_delegate_t> m_run_delegates;
    std::list<hlt_delegate_t> m_hlt_delegates;
    std::list<init_delegate_t> m_init_delegates;
    std::list<fini_delegate_t> m_fini_delegates;

public:

    /// @cond

    vcpu(vcpu &&) noexcept = default;
    vcpu &operator=(vcpu &&) noexcept = default;

    vcpu(const vcpu &) = delete;
    vcpu &operator=(const vcpu &) = delete;

    /// @endcond
};

}

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
