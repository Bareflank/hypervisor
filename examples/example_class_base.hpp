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

#ifndef BSL_EXAMPLE_CLASS_BASE_HPP
#define BSL_EXAMPLE_CLASS_BASE_HPP

namespace bsl
{
    /// @class bsl::example_class_base
    ///
    /// <!-- description -->
    ///   @brief A example of a base class that is compliant with AUTOSAR.
    ///     Note that we must define the rule of 5 (the destructor and copy/move
    ///     constructors/assignment operators must be protected).
    ///
    class example_class_base
    {
    public:
        /// <!-- description -->
        ///   @brief Creates a default bsl::example_class_base
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        example_class_base() noexcept = default;

        /// <!-- description -->
        ///   @brief Simple example of a getter
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns the value of m_data1;
        ///
        [[nodiscard]] constexpr bool
        get() const noexcept
        {
            return m_data1;
        }

        /// <!-- description -->
        ///   @brief Simple example of a setter
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the val to set m_data1 to
        ///
        constexpr void
        set(bool const val) noexcept
        {
            m_data1 = val;
        }

    protected:
        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::example_class_base
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        ~example_class_base() noexcept
        {
            m_data1 = false;
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
        example_class_base(example_class_base const &o) noexcept = default;

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
        example_class_base(example_class_base &&o) noexcept = default;

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
        [[maybe_unused]] example_class_base &
        operator=(example_class_base const &o) &noexcept = default;

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
        [[maybe_unused]] example_class_base &operator=(example_class_base &&o) &noexcept = default;

    private:
        /// @brief dummy data #1
        bool m_data1{true};
    };
}

#endif
