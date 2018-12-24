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

#ifndef MICROCODE_INTEL_X64_H
#define MICROCODE_INTEL_X64_H

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64
{

class vcpu;

/// Microcode Handler
///
/// Provides an interface for handling microcode updates
///
/// TODO:
///
/// Currently, this only disables microcode updates. In the future, we need to
/// add the the following additional APIs
/// - emulate update: provide the ability to emulate the update process,
///   allowing the OS to update the microcode itself.
/// - load custom microcode: we should also provide the ability to upload your
///   own microcode from the VMM's point of view. This way, you can package
///   your own microcode, or vmcall to load microcode as needed.
///
class microcode_handler
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this rdmsr handler
    ///
    microcode_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~microcode_handler() = default;

private:

    vcpu *m_vcpu;

public:

    /// @cond

    microcode_handler(microcode_handler &&) = default;
    microcode_handler &operator=(microcode_handler &&) = default;

    microcode_handler(const microcode_handler &) = delete;
    microcode_handler &operator=(const microcode_handler &) = delete;

    /// @endcond
};

}

#endif
