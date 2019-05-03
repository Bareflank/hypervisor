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

#ifndef EXIT_HANDLER_INTEL_X64_H
#define EXIT_HANDLER_INTEL_X64_H

#include <bfdelegate.h>

#include <list>
#include <array>
#include <memory>

#include <intrinsics.h>

#include "vmcs.h"
#include "../x64/gdt.h"
#include "../x64/idt.h"
#include "../x64/tss.h"

// -----------------------------------------------------------------------------
// Handler Types
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64
{
class vcpu;
class exit_handler;
}

/// Exit handler delegate type
///
using handler_delegate_t = delegate<bool(bfvmm::intel_x64::vcpu *)>;

// -----------------------------------------------------------------------------
// Dispatcher
// -----------------------------------------------------------------------------

/// Private Handler
///
/// This function is called by the exit_handler_entry and is used to
/// dispatch the exit handlers for the class defined here. Ther other way
/// to implement this would be to use a member function in the exit_handler
/// but that would require an even deeper knowledge of the C++ ABI, which
/// we would like to avoid in the ASM code where possible.
///
/// @param vcpu the vcpu associated with the VM exit
/// @param exit_handler the exit handler associated with the provided vcpu
///
extern "C" void handle_exit(
    bfvmm::intel_x64::vcpu *vcpu, bfvmm::intel_x64::exit_handler *exit_handler);

// -----------------------------------------------------------------------------
// Exit Handler
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64
{

/// Exit Handler
///
/// This class is responsible for detecting why a guest exited (i.e. stopped
/// its execution), and handleres the appropriated handler to emulate the
/// instruction that could not execute. Note that this class could be executed
/// a lot, so performance is key here.
///
/// This class works with the VMCS class to provide the bare minimum exit
/// handler needed to execute a 64bit guest, with the TRUE controls being used.
/// In general, the only instruction that needs to be emulated is the CPUID
/// instruction. If more functionality is needed (which is likely), the user
/// can subclass this class, and overload the handlers that are needed. The
/// basics are provided with this class to ease development.
///
class exit_handler
{
public:

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param vcpu The vCPU associated with this exit handler
    ///
    exit_handler(gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~exit_handler() = default;

    /// Add Handler Delegate
    ///
    /// Adds a handler to the handler function. When a VM exit occurs, the
    /// handler handler will call the delegate registered by this function as
    /// as needed. Note that the handlers are called in the reverse order they
    /// are registered (i.e. FIFO).
    ///
    /// @note If the delegate has serviced the VM exit, it should return true,
    ///     otherwise it should return false, and the next delegate registered
    ///     for this VM exit will execute, or an unimplemented exit reason
    ///     error will trigger
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param reason The exit reason for the handler being registered
    /// @param d The delegate being registered
    ///
    void add_handler(
        ::intel_x64::vmcs::value_type reason,
        const handler_delegate_t &d
    );

    /// Add Exit Delegate
    ///
    /// Adds an exit function to the exit list. Exit functions are executed
    /// right after a vCPU exits for any reason. Use this with care because
    /// this function will be executed a lot.
    ///
    /// Note the return value of the delegate is ignored
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param d The delegate being registered
    ///
    void add_exit_handler(
        const handler_delegate_t &d
    );

private:

    std::list<handler_delegate_t> m_exit_handlers;
    std::array<std::list<handler_delegate_t>, 128> m_exit_handlers_array;

public:

    /// @cond

    exit_handler(exit_handler &&) noexcept = default;
    exit_handler &operator=(exit_handler &&) noexcept = default;

    exit_handler(const exit_handler &) = delete;
    exit_handler &operator=(const exit_handler &) = delete;

    /// @endcond

private:

    friend void (::handle_exit)(
        bfvmm::intel_x64::vcpu *vcpu, bfvmm::intel_x64::exit_handler *exit_handler);
};

}

using exit_handler_t = bfvmm::intel_x64::exit_handler;

#endif
