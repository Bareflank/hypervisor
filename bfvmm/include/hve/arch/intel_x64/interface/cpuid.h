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

#ifndef INTERFACE_CPUID_INTEL_X64_H
#define INTERFACE_CPUID_INTEL_X64_H

#include "private.h"

// -----------------------------------------------------------------------------
// Types/Namespaces
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64::cpuid
{
/// Leaf Type
///
/// This defines the CPUID leaf type that is used in this interface
///
using leaf_t = uint64_t;

/// Subleaf Type
///
/// This defines the CPUID subleaf type that is used in this interface
///
using subleaf_t = uint64_t;
}

/// CPUID Namespace
///
/// This defines the CPUID namespace.
///
namespace cpuid_n = bfvmm::intel_x64::cpuid;

// -----------------------------------------------------------------------------
// Interface Defintion
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64::interface
{

/// CPUID
///
/// Defines the CPUID interfaces provided by the vCPU.
///
template<typename IMPL>
class cpuid
{
public:

    /// Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param vcpu the vCPU that is associated with this interface
    ///
    explicit cpuid(gsl::not_null<vcpu *> vcpu) :
        m_impl{vcpu}
    { }

public:

    /// Add Handler
    ///
    /// Adds a VM exit handler. When a VM exit occurs, the registered
    /// handler will be called. More than one handler can be registered. If
    /// a handler returns true, the handler is stating that it is the last
    /// handler to be called, and no other handlers will be executed. If a
    /// handler returns false, the next registered handler will be called
    /// until all of the handlers are called, or another handler in the chain
    /// returns true. If a handler returns true, it must also execute
    /// vcpu->advance() when applicable to ensure the instruction pointer is
    /// advanced. If all of the handlers return false, the base implementation
    /// will return true for you and advance the instruction pointer.
    /// In general, handlers should always return false unless you
    /// explicitly wish to prevent any other handlers from executing (e.g. if
    /// you wish to override the default behavior). Do not call
    /// vcpu->advance() unless you return true, otherwise you will advance and
    /// instruction pointer twice.
    ///
    /// Prior to the handlers being called, the cpuid_execute() function is
    /// called which places the hardware state into the vCPU registers.
    ///
    /// To handle the VM exit, modify the following registers as needed:
    /// - vcpu->rax()
    /// - vcpu->rbx()
    /// - vcpu->rcx()
    /// - vcpu->rdx()
    ///
    /// @expects
    /// @ensures
    ///
    /// @param leaf the cpuid leaf to call d
    /// @param d the handler to call when an exit occurs
    ///
    inline void cpuid_add_handler(
        cpuid_n::leaf_t leaf, const handler_delegate_t &d)
    { m_impl.add_handler(leaf, d); }

    /// Add Emulator
    ///
    /// Emulate the VM exit instead of handling it. An emulator is different
    /// from a regular handler in two different ways:
    /// - The cpuid_execute() function is not called before the emulators, which
    ///   means that the vCPU's registers do not have the hardware's values in
    ///   them, nor will the hardware's values be written to hardware for you.
    ///   This ensures that you do not accidentally write the hardware state to
    ///   the vCPU, leaking information that might be sensitive. If the hardware
    ///   state needs to be accessed, you can always call cpuid_execute()
    ///   yourself, just be careful.
    /// - At least one emulator must return true. The base implementation will
    ///   not return true for an emulator. If at least one emulator doesn't
    ///   return true, an unhandled vm exit exception will occur. The emulator
    ///   that returns true must also call vcpu->advance() when applicable. As
    ///   a result, the last emulator to be called will typically return by
    ///   calling "return vcpu->advance();"
    ///
    /// In general, emulators are used to create fake versions of hardware.
    /// This is mostly useful for guest vCPUs, where hardware is being faked,
    /// or for hardware that is added to host vCPUs (like Bareflank specific
    /// regsiters). Unless you need to fake hardware, likely you should be
    /// using add_handler() and not add_emulator().
    ///
    /// Note: Once an emulator is added, regular handlers will no longer be
    /// called including the handlers provided by the base hypervisor. Adding
    /// an emulator handler tells the APIs that you are taking on the
    /// responsibility of properly handling the hardware, including ensuring
    /// that the hardware (or fake hardware) is consistent with what the base
    /// hypervisor provides, including any assumptions it is making. Use wisely.
    ///
    /// To handle the VM exit, modify the following registers as needed:
    /// - vcpu->rax()
    /// - vcpu->rbx()
    /// - vcpu->rcx()
    /// - vcpu->rdx()
    ///
    /// @expects
    /// @ensures
    ///
    /// @param leaf the address to emulate
    /// @param d the handler to call when an exit occurs
    ///
    inline void cpuid_add_emulator(
        cpuid_n::leaf_t leaf, const handler_delegate_t &d)
    { m_impl.add_emulator(leaf, d); }

    /// Execute
    ///
    /// Executes the CPUID instruction and populates the vCPU's registers as
    /// follows:
    /// - [rax, rbx, rcx, rdx] = cpuid
    /// - vcpu->rax() = rax
    /// - vcpu->rbx() = rbx
    /// - vcpu->rcx() = rcx
    /// - vcpu->rdx() = rdx
    ///
    /// Note: This function can be used inside of an emulator to access hardware
    /// similar to a regular handler. This is useful when you want to use an
    /// emulator, but still need to access hardware. Just be aware that the
    /// safety protections that an emulator provides are removed.
    ///
    /// @expects
    /// @ensures
    ///
    inline void cpuid_execute() noexcept
    { m_impl.execute(this); }

    /// Emulate
    ///
    /// Emulates the CPUID instruction by populating the vCPU registers with
    /// values provided to this function. This function is equivalent to:
    ///
    /// - vcpu->rax() = 0xFFFFFFFF & rax
    /// - vcpu->rbx() = 0xFFFFFFFF & rbx
    /// - vcpu->rcx() = 0xFFFFFFFF & rcx
    /// - vcpu->rdx() = 0xFFFFFFFF & rdx
    ///
    /// @expects
    /// @ensures
    ///
    /// @param rax the CPUID eax return value
    /// @param rbx the CPUID ebx return value
    /// @param rcx the CPUID ecx return value
    /// @param rdx the CPUID edx return value
    ///
    inline void cpuid_emulate(
        reg_t rax, reg_t rbx, reg_t rcx, reg_t rdx) noexcept
    { m_impl.emulate(this, rax, rbx, rcx, rdx); }

    /// CPUID Leaf (VMExit-Only)
    ///
    /// This function will return the CPUID leaf that generated the current
    /// VMExit. If this function is called outside of a VMExit or from a VMExit
    /// that is not a CPUID VMExit, this function will throw.
    ///
    /// @expects executing in a CPUID VMExit
    /// @ensures
    ///
    /// @return the value of rax when the VMEXit occurred
    ///
    inline cpuid_n::leaf_t cpuid_leaf() const
    { return m_impl.leaf(static_cast<const vcpu *>(this)); }

    /// CPUID Subleaf (VMExit-Only)
    ///
    /// This function will return the CPUID subleaf that generated the current
    /// VMExit. If this function is called outside of a VMExit or from a VMExit
    /// that is not a CPUID VMExit, this function will throw.
    ///
    /// @expects executing in a CPUID VMExit
    /// @ensures
    ///
    /// @return the value of rcx when the VMEXit occurred
    ///
    inline cpuid_n::subleaf_t cpuid_subleaf() const
    { return m_impl.subleaf(this); }

private:

    PRIVATE_INTERFACES(cpuid);
};

}

// -----------------------------------------------------------------------------
// Root Init/Fini Functions
// -----------------------------------------------------------------------------

/// vCPU Init (Root)
///
/// This function is called whenever a vCPU is being initialized in root mode
/// (i.e. the vCPU is executing from an exit handler in ring -1). Extensions
/// can override this function to provide their own custom initialization code.
///
/// @param vcpu the vcpu being initialized
///
void vcpu_init_root(vcpu_t *vcpu);

/// vCPU Fini (Root)
///
/// This function is called whenever a vCPU is being finalized in root mode
/// (i.e. the vCPU is executing from an exit handler in ring -1). Extensions
/// can override this function to provide their own custom finalization code.
///
/// @param vcpu the vcpu being finalized
///
void vcpu_fini_root(vcpu_t *vcpu);

// -----------------------------------------------------------------------------
// Wrappers
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64::cpuid
{
/// Add Handler (Wrapper)
///
/// Wraps the cpuid_add_handler() function.
///
/// @code
/// vcpu->cpuid_add_handler(...);
/// @endcode
///
/// or
///
/// @code
/// cpuid::add_handler(vcpu, ...);
/// @endcode
///
/// @expects vcpu != nullptr
/// @ensures
///
/// @param vcpu a pointer to the cpuid interface
/// @param args cpuid_add_handler() arguments
///
template<typename IMPL, typename... Args>
inline void add_handler(
    gsl::not_null<interface::cpuid<IMPL> *> vcpu,
    Args &&...args)
{ vcpu->cpuid_add_handler(std::forward<Args>(args)...); }

/// Add Emulator (Wrapper)
///
/// Wraps the cpuid_add_emulator() function.
///
/// @code
/// vcpu->cpuid_add_emulator(...);
/// @endcode
///
/// or
///
/// @code
/// cpuid::add_emulator(vcpu, ...);
/// @endcode
///
/// @expects vcpu != nullptr
/// @ensures
///
/// @param vcpu a pointer to the cpuid interface
/// @param args cpuid_add_emulator() arguments
///
template<typename IMPL, typename... Args>
inline void add_emulator(
    gsl::not_null<interface::cpuid<IMPL> *> vcpu,
    Args &&...args)
{ vcpu->cpuid_add_emulator(std::forward<Args>(args)...); }

/// Execute (Wrapper)
///
/// Wraps the cpuid_execute() function.
///
/// @code
/// vcpu->cpuid_execute(...);
/// @endcode
///
/// or
///
/// @code
/// cpuid::execute(vcpu, ...);
/// @endcode
///
/// @expects vcpu != nullptr
/// @ensures
///
/// @param vcpu a pointer to the cpuid interface
///
template<typename IMPL>
inline void execute(
    gsl::not_null<interface::cpuid<IMPL> *> vcpu)
{ vcpu->cpuid_execute(); }

/// Emulate (Wrapper)
///
/// Wraps the cpuid_emulate() function.
///
/// @code
/// vcpu->cpuid_emulate(...);
/// @endcode
///
/// or
///
/// @code
/// cpuid::emulate(vcpu, ...);
/// @endcode
///
/// @expects vcpu != nullptr
/// @ensures
///
/// @param vcpu a pointer to the cpuid interface
/// @param args cpuid_emulate() arguments
///
template<typename IMPL, typename... Args>
inline void emulate(
    gsl::not_null<interface::cpuid<IMPL> *> vcpu,
    Args &&...args)
{ vcpu->cpuid_emulate(std::forward<Args>(args)...); }

/// Leaf (Wrapper)
///
/// Wraps the cpuid_leaf() function.
///
/// @code
/// vcpu->cpuid_leaf(...);
/// @endcode
///
/// or
///
/// @code
/// cpuid::leaf(vcpu, ...);
/// @endcode
///
/// @expects vcpu != nullptr
/// @ensures
///
/// @param vcpu a pointer to the cpuid interface
/// @param args cpuid_leaf() arguments
///
template<typename IMPL>
inline cpuid_n::leaf_t leaf(
    gsl::not_null<const interface::cpuid<IMPL> *> vcpu)
{ return vcpu->cpuid_leaf(); }

/// Subleaf (Wrapper)
///
/// Wraps the cpuid_subleaf() function.
///
/// @code
/// vcpu->cpuid_subleaf(...);
/// @endcode
///
/// or
///
/// @code
/// cpuid::subleaf(vcpu, ...);
/// @endcode
///
/// @expects vcpu != nullptr
/// @ensures
///
/// @param vcpu a pointer to the cpuid interface
/// @param args cpuid_subleaf() arguments
///
template<typename IMPL>
inline cpuid_n::subleaf_t subleaf(
    gsl::not_null<const interface::cpuid<IMPL> *> vcpu)
{ return vcpu->cpuid_subleaf(); }
}

/// @cond

namespace bfvmm::intel_x64::cpuid
{
template<typename IMPL, typename... Args>
inline void add_handler(
    interface::cpuid<IMPL> *vcpu, Args &&...args)
{
    add_handler(
        gsl::not_null<interface::cpuid<IMPL> *>(vcpu),
        std::forward<Args>(args)...
    );
}

template<typename IMPL, typename... Args>
inline void add_emulator(
    interface::cpuid<IMPL> *vcpu, Args &&...args)
{
    add_emulator(
        gsl::not_null<interface::cpuid<IMPL> *>(vcpu),
        std::forward<Args>(args)...
    );
}

template<typename IMPL>
inline void execute(
    interface::cpuid<IMPL> *vcpu)
{ execute(gsl::not_null<interface::cpuid<IMPL> *>(vcpu)); }

template<typename IMPL, typename... Args>
inline void emulate(
    interface::cpuid<IMPL> *vcpu, Args &&...args)
{
    emulate(
        gsl::not_null<interface::cpuid<IMPL> *>(vcpu),
        std::forward<Args>(args)...
    );
}

template<typename IMPL>
inline cpuid_n::leaf_t leaf(
    const interface::cpuid<IMPL> *vcpu)
{ return leaf(gsl::not_null<const interface::cpuid<IMPL> *>(vcpu)); }

template<typename IMPL>
inline cpuid_n::subleaf_t subleaf(
    const interface::cpuid<IMPL> *vcpu)
{ return subleaf(gsl::not_null<const interface::cpuid<IMPL> *>(vcpu)); }
}

/// @endcond

#endif
