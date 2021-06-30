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

#ifndef CPUID_COMMANDS_HPP
#define CPUID_COMMANDS_HPP

#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>

namespace loader
{
    /// @brief defines the value of EAX for all CPUID commands
    constexpr auto CPUID_COMMAND_EAX{0x400000FF_u32};
    /// @brief defines the value of ECX for the CPUID stop command
    constexpr auto CPUID_COMMAND_ECX_STOP{0xBF000000_u32};
    /// @brief defines the value of ECX for the CPUID report on command
    constexpr auto CPUID_COMMAND_ECX_REPORT_ON{0xBF000001_u32};
    /// @brief defines the value of ECX for the CPUID report off command
    constexpr auto CPUID_COMMAND_ECX_REPORT_OFF{0xBF000002_u32};

    /// @brief defines the value of RAX on success
    constexpr auto CPUID_COMMAND_RAX_SUCCESS{0x0_u64};
    /// @brief defines the value of RAX on failure
    constexpr auto CPUID_COMMAND_RAX_FAILURE{0x1_u64};
}

#endif
