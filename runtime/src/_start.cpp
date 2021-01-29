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
#include <bsl/cstring.hpp>

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

    /// TODO:
    /// - Find out how the compiler is compiling memset and memcpy and make
    ///   sure there isn't a faster way to implement these (without SSE).
    ///

    /// <!-- description -->
    ///   @brief Same as std::memset.
    ///
    /// <!-- inputs/outputs -->
    ///   @param dst a pointer to the memory to set
    ///   @param ch the value to set the memory to
    ///   @param num the total number of bytes to set
    ///   @return Returns the same result as std::memset.
    ///
    [[maybe_unused]] extern "C" auto
    memset(void *const dst, bsl::char_type const ch, bsl::uintmax const num) -> void *
    {
        return bsl::builtin_memset(dst, ch, num);
    }

    /// <!-- description -->
    ///   @brief Same as std::memcpy.
    ///
    /// <!-- inputs/outputs -->
    ///   @param dst a pointer to the memory to copy to
    ///   @param src a pointer to the memory to copy from
    ///   @param count the total number of bytes to copy
    ///   @return Returns the same result as std::memcpy.
    ///
    [[maybe_unused]] extern "C" auto
    memcpy(void *const dst, void const *const src, bsl::uintmax const count) noexcept -> void *
    {
        return bsl::builtin_memcpy(dst, src, count);
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
