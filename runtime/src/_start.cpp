/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#include <mk_interface.hpp>

#include <bsl/cstdint.hpp>
#include <bsl/cstdio.hpp>

extern "C"
{
    /// @brief provides the stack guard
    constinit bsl::uintmax __stack_chk_guard{0xDEADBEEFDEADBEEF};    // NOLINT

    /// <!-- description -->
    ///   @brief Used to detect if stack corruption occurs.
    ///
    void
    __stack_chk_fail() noexcept    // NOLINT
    {
        bsl::fputs("stack smashing detected\n");
        syscall::bf_control_op_exit();
    }
}

namespace runtime
{
    /// <!-- description -->
    ///   @brief Implements the extension's main entry point
    ///
    /// <!-- inputs/outputs -->
    ///   @param version the version of the spec implemented by the
    ///     microkernel. This can be used to ensure the extension and the
    ///     microkernel speak the same ABI.
    ///
    extern "C" void ext_main_entry(bsl::safe_uint32 const &version) noexcept;

    /// <!-- description -->
    ///   @brief Provides the _start function
    ///
    /// <!-- inputs/outputs -->
    ///   @param version the version of the spec implemented by the
    ///     microkernel. This can be used to ensure the extension and the
    ///     microkernel speak the same ABI.
    ///
    extern "C" void
    _start(bsl::uint32 const version) noexcept
    {
        ext_main_entry(version);
    }
}
