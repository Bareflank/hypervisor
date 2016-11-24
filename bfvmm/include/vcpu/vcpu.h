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

#ifndef VCPU_H
#define VCPU_H

#include <string>
#include <memory>

#include <vcpuid.h>
#include <user_data.h>
#include <debug_ring/debug_ring.h>

/// Virtual CPU
///
/// The vCPU represents a "core" for a virtual machine. There are different
/// types of virtual machines (the host VM and guest VM being good examples)
/// but in either case, a set of vCPUs must be provided.
///
/// For the host VM (also called the hardware domain), 1 vCPU must exist
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
/// The goal with Bareflank is to allow any number of virtual cores, regardless
/// of the physical core configuration. To support this, vCPUs
/// can be scheduled on any core, and the ID does not correlate with
/// a physical core. It's up to the vCPU implementation to figure out how to
/// schedule a core on the proper vCPU. In the case of Intel, this means that
/// the VMCS class and the exit handler will have to store their own physical
/// core ID that is different from the vCPU ID. If the exit handler has to
/// schedule a VMCS and it detects the VMCS used to be on a different core,
/// it will have to perform a transition.
///
/// This generic vCPU class not only provides the base class that architecture
/// specific vCPUs will be created from, but it also provides some of the base
/// functionality that is common between all vCPUs.
///
/// Each vCPU is given its own debug ring. The bootstrap core is a special
/// core. All std::cout that is not wrapped in the output_to_vcpu function
/// is redirected to serial and the bootstrap core, which is vcpuid == 0,
/// or the first vCPU to be created on the host OS. Each debug ring provides
/// a set of tags that can be used to identify the debug ring from a memory
/// dump. The vCPU ID is also provided so that you can figure out which
/// debug ring you're looking at.
///
/// The init, fini, run and hlt functions must be executed in the proper
/// order. Each vCPU must be initialized and finalized. The destructor for
/// the vCPU should not be used as destructors are labeled "noexcept" by
/// default. Instead the init and fini functions act as constructors /
/// destructors that can handle errors if they should arise. Doing this
/// will also provide debugging support with the debug rings.
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
class vcpu
{
public:

    /// Constructor
    ///
    /// Creates a vCPU with the provided id and debug ring. This constructor
    /// provides a means to override and replace the internal resources of the
    /// vCPU. Note that if one of the resources is set to nullptr, a default
    /// will be constructed in its place, providing a means to select which
    /// internal components to override.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param id the id of the vcpu
    /// @param dr the debug ring the vcpu should use. If you provide nullptr,
    ///     a default debug ring will be created.
    ///
    vcpu(vcpuid::type id, std::unique_ptr<debug_ring> dr = nullptr);

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual ~vcpu() = default;

    /// Init vCPU
    ///
    /// Initializes the vCPU. This function should only be run once. To
    /// re-execute this function, fini should be used first. Both init
    /// and fini are used in place of the constructor / destructor for some
    /// logic that certainly could generate an exception.
    ///
    /// @note: subclasses must call this function if it's overridden
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void init(user_data *data = nullptr);

    /// Fini vCPU
    ///
    /// Finalizes the vCPU. This function should only be run once. To
    /// re-execute this function, init should be used first. Both init
    /// and fini are used in place of the constructor / destructor for some
    /// logic that certainly could generate an exception.
    ///
    /// @note: subclasses must call this function if it's overridden
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void fini(user_data *data = nullptr);

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
    /// @note: subclasses must call this function if it's overridden
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void run(user_data *data = nullptr);

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
    /// @note: subclasses must call this function if it's overridden
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void hlt(user_data *data = nullptr);

    /// vCPU Id
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return the vCPU's id
    ///
    virtual vcpuid::type id() const
    { return m_id; }

    /// Is Running
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if the vCPU is running, false otherwise.
    ///
    virtual bool is_running()
    { return m_is_running; }

    /// Is Initialized
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if the vCPU is initialized, false otherwise.
    ///
    virtual bool is_initialized()
    { return m_is_initialized; }

    /// Is Bootstrap vCPU
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if this vCPU is the bootstrap vCPU, false otherwise
    ///
    virtual bool is_bootstrap_vcpu()
    { return m_id == 0; }

    /// Is Host VM vCPU
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if this vCPU belongs to the host VM, false otherwise
    ///
    virtual bool is_host_vm_vcpu()
    { return (m_id & (vcpuid::guest_mask & ~vcpuid::reserved)) == 0; }

    /// Is Guest VM vCPU
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if this vCPU belongs to a guest VM, false otherwise
    ///
    virtual bool is_guest_vm_vcpu()
    { return (m_id & (vcpuid::guest_mask & ~vcpuid::reserved)) != 0; }

    /// Write to Debug Ring
    ///
    /// Each vCPU has its own debug ring. If this is the bootstrap core
    /// (vcpuid == 0), all std::cout / std::cerr calls go to this vCPU.
    /// To redirect output to a core other than the bootstrap core, use the
    /// output_to_vcpu function in debug.h.
    ///
    /// Note that when using this function, output does not go to serial.
    /// This can cause issues when debugging a core specific problem that
    /// hangs the system (as getting the debug ring requires a running
    /// system). To overcome this issue, each debug ring has a unique tag
    /// that can be used to identify the debug ring from a memory dump.
    /// Right next to the tag is the vCPU's ID that can be used to identify
    /// which vCPU the debug ring belongs to. From there, one must simply
    /// manually parse the ring.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param str the string to write to the debug ring. If the ring is
    ///     bigger than DEBUG_RING_SIZE, the write is ignored.
    ///
    virtual void write(const std::string &str) noexcept;

private:

    vcpuid::type m_id;
    std::unique_ptr<debug_ring> m_debug_ring;

    bool m_is_running;
    bool m_is_initialized;
};

#endif
