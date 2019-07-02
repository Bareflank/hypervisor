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

#ifndef VCPU_FACTORY_H
#define VCPU_FACTORY_H

#include <memory>
#include "vcpu.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm
{

/// vCPU Factory
///
/// This class is used by the vcpu_manager to create vCPUs. Specifically,
/// this class provides a seem that allows users of Bareflank to replace the
/// default vCPU with their own, custom vCPUs that extend the functionality
/// of Bareflank above and beyond what is already provided. This seem also
/// provides a means to unit test the vcpu_manager.
///
class vcpu_factory
{
public:

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    vcpu_factory() noexcept = default;

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual ~vcpu_factory() = default;

    /// Make vCPU
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param vcpuid the vcpuid for the vcpu to create
    /// @param data a pointer to user defined data
    /// @return returns a pointer to a newly created vCPU.
    ///
    virtual std::unique_ptr<vcpu> make(
        vcpuid::type vcpuid, void *data);

public:

    /// @cond

    vcpu_factory(vcpu_factory &&) noexcept = default;
    vcpu_factory &operator=(vcpu_factory &&) noexcept = default;

    vcpu_factory(const vcpu_factory &) = delete;
    vcpu_factory &operator=(const vcpu_factory &) = delete;

    /// @endcond
};
}

#endif
