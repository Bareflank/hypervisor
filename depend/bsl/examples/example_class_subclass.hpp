/// @copyright
/// Copyright (C) 2019 Assured Information Security, Inc.
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

#ifndef BSL_EXAMPLE_CLASS_SUBCLASS_HPP
#define BSL_EXAMPLE_CLASS_SUBCLASS_HPP

#include "example_class_base.hpp"
#include <bsl/move.hpp>
#include <bsl/swap.hpp>

namespace bsl
{
    /// @class bsl::example_class_subclass
    ///
    /// <!-- description -->
    ///   @brief A example of a subclass that is compliant with AUTOSAR.
    ///
    /// <!-- notes -->
    ///   @note This class is not trivial because it has a non-default
    ///     destructor (which also means it is not a literal type). This
    ///     class does not have a standard layout because both the subclass
    ///     and the base class have member variables. Since this class is not
    ///     trivial and does not have a standard layout, it is not a POD, nor
    ///     is this class empty.
    ///
    class example_class_subclass final : public example_class_base
    {
    public:
        /// <!-- description -->
        ///   @brief Creates a default bsl::example_class_subclass
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        example_class_subclass() noexcept = default;

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::example_class_subclass
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        ~example_class_subclass() noexcept
        {
            m_data2 = false;
        }

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        example_class_subclass(example_class_subclass const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        example_class_subclass(example_class_subclass &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] example_class_subclass &
        operator=(example_class_subclass const &o) &noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] example_class_subclass &
        operator=(example_class_subclass &&o) &noexcept = default;

    private:
        /// @brief dummy data #1
        bool m_data2{true};
    };
}

#endif
