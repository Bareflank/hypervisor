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
///
/// @file reference_wrapper.hpp
///

#ifndef BSL_REFERENCE_WRAPPER_HPP
#define BSL_REFERENCE_WRAPPER_HPP

#include "addressof.hpp"
#include "decay.hpp"
#include "declval.hpp"
#include "enable_if.hpp"
#include "forward.hpp"
#include "invoke_result.hpp"
#include "is_same.hpp"

namespace bsl
{
    namespace details
    {
        /// <!-- description -->
        ///   @brief Used to determine if a conversion is possible as well as
        ///     performs any needed conversions when used.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type to convert to
        ///   @param val the thing being converted
        ///   @return A reference to the converted type T
        ///
        template<typename T>
        constexpr T &
        FUN(T &val) noexcept
        {
            return val;
        }

        /// <!-- description -->
        ///   @brief Prevents a reference_wrapper from storing the address
        ///     of an rvalue, which could result in UB. This uses the same
        ///     syntax as the function above to ensure conversions do not
        ///     generate this issue.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type to convert to
        ///   @param val the thing being converted
        ///
        template<typename T>
        void FUN(T &&val) = delete;
    }

    /// @class bsl::reference_wrapper
    ///
    /// <!-- description -->
    ///   @brief bsl::reference_wrapper is a class template that wraps a
    ///     reference. Unlike the std::reference_wrapper, the implicit
    ///     conversion operator is not supported as that would not be
    ///     compliant with AUTOSAR. We also do not add the assignment
    ///     operator as that would result in needing to define the rule of 5
    ///     which is not needed (there is no harm in allowing moves as
    ///     they result in the same thing as a copy).
    ///   @include example_reference_wrapper_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type of reference to wrap
    ///
    template<typename T>
    class reference_wrapper final
    {
    public:
        /// <!-- description -->
        ///   @brief Used to initialize a reference_wrapper by getting an
        ///     address to the provided "val" and storing the address for
        ///     use later.
        ///   @include reference_wrapper/example_reference_wrapper_constructor.hpp
        ///
        ///   SUPPRESSION: PRQA 2023 - exception required
        ///   - We suppress this because A13-3-1 states that you should not
        ///     overload functions that contain a forwarding reference because
        ///     it is confusing to the user. In this case, there is nothing
        ///     ambiguous about this situation as there is only one constructor
        ///     so there are no additional constructors to confuse the API with.
        ///     It should also be noted that the C++ specificatino states that
        ///     this is how std::reference_wrapper should be implemented.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U the type that defines "val"
        ///   @param val the thing to get the address of and store.
        ///
        /// <!-- exceptions -->
        ///   @throw throws if converting U to T throws
        ///
        template<
            typename U,
            enable_if_t<!is_same<decay_t<U>, reference_wrapper>::value> = true,
            typename = decltype(details::FUN<T>(declval<U>()))>
        explicit constexpr reference_wrapper(U &&val)    // PRQA S 2023 // NOLINT
            noexcept(noexcept(details::FUN<T>(bsl::forward<U>(val))))
            : m_ptr{addressof(details::FUN<T>(bsl::forward<U>(val)))}
        {}

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        ///   SUPPRESSION: PRQA 2023 - exception required
        ///   - We suppress this because A13-3-1 states that you should not
        ///     overload functions that contain a forwarding reference because
        ///     it is confusing to the user. In this case, there is nothing
        ///     ambiguous about this situation as there is only one constructor
        ///     so there are no additional constructors to confuse the API with.
        ///     It should also be noted that the C++ specificatino states that
        ///     this is how std::reference_wrapper should be implemented.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr reference_wrapper(reference_wrapper const &o)    // PRQA S 2023
            noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        ///   SUPPRESSION: PRQA 2023 - exception required
        ///   - We suppress this because A13-3-1 states that you should not
        ///     overload functions that contain a forwarding reference because
        ///     it is confusing to the user. In this case, there is nothing
        ///     ambiguous about this situation as there is only one constructor
        ///     so there are no additional constructors to confuse the API with.
        ///     It should also be noted that the C++ specificatino states that
        ///     this is how std::reference_wrapper should be implemented.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr reference_wrapper(reference_wrapper &&o) noexcept = default;    // PRQA S 2023

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        ///   SUPPRESSION: PRQA 2023 - exception required
        ///   - We suppress this because A13-3-1 states that you should not
        ///     overload functions that contain a forwarding reference because
        ///     it is confusing to the user. In this case, there is nothing
        ///     ambiguous about this situation as there is only one constructor
        ///     so there are no additional constructors to confuse the API with.
        ///     It should also be noted that the C++ specificatino states that
        ///     this is how std::reference_wrapper should be implemented.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr reference_wrapper &    // PRQA S 2023
        operator=(reference_wrapper const &o) &noexcept = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        ///   SUPPRESSION: PRQA 2023 - exception required
        ///   - We suppress this because A13-3-1 states that you should not
        ///     overload functions that contain a forwarding reference because
        ///     it is confusing to the user. In this case, there is nothing
        ///     ambiguous about this situation as there is only one constructor
        ///     so there are no additional constructors to confuse the API with.
        ///     It should also be noted that the C++ specificatino states that
        ///     this is how std::reference_wrapper should be implemented.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr reference_wrapper &    // PRQA S 2023
        operator=(reference_wrapper &&o) &noexcept = default;

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::reference_wrapper
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        ~reference_wrapper() noexcept = default;

        /// <!-- description -->
        ///   @brief Returns a reference to the thing that is wrapped. This is
        ///     done by taking the stored address and returning a reference
        ///     instead of an address.
        ///   @include reference_wrapper/example_reference_wrapper_get.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reference to the wrapped thing
        ///
        [[nodiscard]] constexpr T &
        get() const noexcept
        {
            return *m_ptr;
        }

        /// <!-- description -->
        ///   @brief Invokes the reference_wrapper as if it were a function.
        ///   @include reference_wrapper/example_reference_wrapper_functor.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam ARGS the types of arguments to pass to the wrapped
        ///     function.
        ///   @param a the arguments to pass to the wrapped function.
        ///   @return Returns the result of the wrapped function given the
        ///     provided arguments.
        ///
        /// <!-- exceptions -->
        ///   @throw throws if the wrapped function throws
        ///
        template<typename... ARGS>
        [[nodiscard]] constexpr invoke_result_t<T &, ARGS...>
        operator()(ARGS &&... a) const
        {
            return invoke(this->get(), bsl::forward<ARGS>(a)...);
        }

    private:
        /// @brief stores the address of the wrapped reference
        T *m_ptr;
    };

    /// @brief Provides a UDDG for the reference_wrapper.
    template<typename T>
    reference_wrapper(T &)->reference_wrapper<T>;
}

#endif
