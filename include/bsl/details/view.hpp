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

#ifndef BSL_DETAILS_VIEW_HPP
#define BSL_DETAILS_VIEW_HPP

#include "../cstdint.hpp"
#include "../enable_if.hpp"
#include "../forward.hpp"
#include "../invoke.hpp"
#include "../is_invocable.hpp"
#include "../is_nothrow_invocable.hpp"
#include "../numeric_limits.hpp"

namespace bsl
{
    namespace details
    {
        template<typename T>
        class view    // NOLINT
        {
            /// @brief stores a pointer to the data being viewed
            T *m_data;
            /// @brief stores the number of elements being viewed
            bsl::uintmax m_size;

        public:
            /// <!-- description -->
            ///   @brief Default constructor
            ///   @include
            ///   @related
            ///
            /// <!-- notes -->
            ///   @note
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            /// <!-- inputs/outputs -->
            ///   @tparam
            ///   @param
            ///   @return
            ///
            constexpr view() noexcept = default;

            template<bsl::uintmax N>
            constexpr view(T (&arr)[N]) noexcept    // NOLINT
                : m_data{arr}, m_size{N}
            {}

            constexpr view(T *data, bsl::uintmax size) noexcept    // --
                : m_data{data}, m_size{size}
            {
                if ((nullptr == m_data) || (0 == m_size)) {
                    *this = view{};
                }
            }

            /// <!-- description -->
            ///   @brief Returns a pointer to the instance of T stored at index
            ///     "index". If the index is out of bounds, or the view is invalid,
            ///     this function returns a nullptr.
            ///   @include view/at_if.cpp
            ///
            ///   SUPPRESSION: PRQA 4211 - false positive
            ///   - We suppress this because M9-3-3 states that if a function
            ///     doesn't modify a class member, it should be marked as const.
            ///     This function, however, returns a non-const pointer to an
            ///     object stored internal to the class, meaning it cannot be
            ///     labeled const without breaking other AUTOSAR rules. This
            ///     is no different than returning a non-const refernce which
            ///     does not trip up PRQA so this must be a bug.
            ///
            ///   SUPPRESSION: PRQA 3706 - false positive
            ///   - We suppress this because M5-0-15 states that pointer arithmetic
            ///     is not allowed, and instead direct indexing or an array should
            ///     be used. This took a while to sort out. The short story is,
            ///     this is a false positive. M5-0-15 wants you to do ptr[X]
            ///     instead of *(ptr + X), which is what we are doing here. This
            ///     example is clearly shown in the second to last line in the
            ///     example that MISRA 2008 provides. The language for this was
            ///     cleaned up in MISRA 2012 as well. PRQA should be capable of
            ///     detecting this.
            ///
            ///   SUPPRESSION: PRQA 4024 - false positive
            ///   - We suppress this because A9-3-1 states that pointer we should
            ///     not provide a non-const reference or pointer to private
            ///     member function, unless the class mimics a smart pointer or
            ///     a containter. This class mimics a container.
            ///
            /// <!-- contracts -->
            ///   @pre the view must be valid and the index must be less than the
            ///     size of the array the view is pointer to. If not, a nullptr
            ///     is returned.
            ///   @post none
            ///
            /// <!-- inputs/outputs -->
            ///   @param index the index of the instance to return
            ///   @return Returns a pointer to the instance of T stored at index
            ///     "index". If the index is out of bounds, or the view is invalid,
            ///     this function returns a nullptr.
            ///
            [[nodiscard]] constexpr T *
            at_if(bsl::uintmax const index) noexcept    // PRQA S 4211
            {
                if ((nullptr == m_data) || (index >= m_size)) {
                    return nullptr;
                }

                return &m_data[index];    // PRQA S 3706, 4024 // NOLINT
            }

            /// <!-- description -->
            ///   @brief Returns a pointer to the instance of T stored at index
            ///     "index". If the index is out of bounds, or the view is invalid,
            ///     this function returns a nullptr.
            ///   @include view/at_if.cpp
            ///
            ///   SUPPRESSION: PRQA 3706 - false positive
            ///   - We suppress this because M5-0-15 states that pointer arithmetic
            ///     is not allowed, and instead direct indexing or an array should
            ///     be used. This took a while to sort out. The short story is,
            ///     this is a false positive. M5-0-15 wants you to do ptr[X]
            ///     instead of *(ptr + X), which is what we are doing here. This
            ///     example is clearly shown in the second to last line in the
            ///     example that MISRA 2008 provides. The language for this was
            ///     cleaned up in MISRA 2012 as well. PRQA should be capable of
            ///     detecting this.
            ///
            /// <!-- contracts -->
            ///   @pre the view must be valid and the index must be less than the
            ///     size of the array the view is pointer to. If not, a nullptr
            ///     is returned.
            ///   @post none
            ///
            /// <!-- inputs/outputs -->
            ///   @param index the index of the instance to return
            ///   @return Returns a pointer to the instance of T stored at index
            ///     "index". If the index is out of bounds, or the view is invalid,
            ///     this function returns a nullptr.
            ///
            [[nodiscard]] constexpr T const *
            at_if(bsl::uintmax const index) const noexcept
            {
                if ((nullptr == m_data) || (index >= m_size)) {
                    return nullptr;
                }

                return &m_data[index];    // PRQA S 3706 // NOLINT
            }

            /// <!-- description -->
            ///   @brief Returns a pointer to the instance of T stored at index
            ///     "0". If the index is out of bounds, or the view is invalid,
            ///     this function returns a nullptr.
            ///   @include view/front_if.cpp
            ///
            /// <!-- contracts -->
            ///   @pre the view must be valid and contain data. If not, a nullptr
            ///     is returned.
            ///   @post none
            ///
            /// <!-- inputs/outputs -->
            ///   @return Returns a pointer to the instance of T stored at index
            ///     "0". If the index is out of bounds, or the view is invalid,
            ///     this function returns a nullptr.
            ///
            [[nodiscard]] constexpr T *
            front_if() noexcept
            {
                return this->at_if(0);
            }

            /// <!-- description -->
            ///   @brief Returns a pointer to the instance of T stored at index
            ///     "0". If the index is out of bounds, or the view is invalid,
            ///     this function returns a nullptr.
            ///   @include view/front_if.cpp
            ///
            /// <!-- contracts -->
            ///   @pre the view must be valid and contain data. If not, a nullptr
            ///     is returned.
            ///   @post none
            ///
            /// <!-- inputs/outputs -->
            ///   @return Returns a pointer to the instance of T stored at index
            ///     "0". If the index is out of bounds, or the view is invalid,
            ///     this function returns a nullptr.
            ///
            [[nodiscard]] constexpr T const *
            front_if() const noexcept
            {
                return this->at_if(0);
            }

            /// <!-- description -->
            ///   @brief Returns a pointer to the instance of T stored at index
            ///     "size() - 1". If the index is out of bounds, or the view is
            ///     invalid, this function returns a nullptr.
            ///   @include view/back_if.cpp
            ///
            /// <!-- contracts -->
            ///   @pre the view must be valid and contain data. If not, a nullptr
            ///     is returned.
            ///   @post none
            ///
            /// <!-- inputs/outputs -->
            ///   @return Returns a pointer to the instance of T stored at index
            ///     "size() - 1". If the index is out of bounds, or the view is
            ///     invalid, this function returns a nullptr.
            ///
            [[nodiscard]] constexpr T *
            back_if() noexcept
            {
                return this->at_if(m_size > 0 ? m_size - 1 : 0);
            }

            /// <!-- description -->
            ///   @brief Returns a pointer to the instance of T stored at index
            ///     "size() - 1". If the index is out of bounds, or the view is
            ///     invalid, this function returns a nullptr.
            ///   @include view/back_if.cpp
            ///
            /// <!-- contracts -->
            ///   @pre the view must be valid and contain data. If not, a nullptr
            ///     is returned.
            ///   @post none
            ///
            /// <!-- inputs/outputs -->
            ///   @return Returns a pointer to the instance of T stored at index
            ///     "size() - 1". If the index is out of bounds, or the view is
            ///     invalid, this function returns a nullptr.
            ///
            [[nodiscard]] constexpr T const *
            back_if() const noexcept
            {
                return this->at_if(m_size > 0 ? m_size - 1 : 0);
            }

            [[nodiscard]] constexpr T *
            data() noexcept
            {
                return m_data;
            }

            [[nodiscard]] constexpr T const *
            data() const noexcept
            {
                return m_data;
            }

            [[nodiscard]] constexpr bsl::uintmax
            size() const noexcept
            {
                return m_size;
            }

            [[nodiscard]] constexpr bsl::uintmax
            max_size() const noexcept
            {
                return numeric_limits<bsl::uintmax>::max() / sizeof(T);
            }

            [[nodiscard]] constexpr bsl::uintmax
            size_bytes() const noexcept
            {
                return m_size * sizeof(T);
            }

            [[nodiscard]] constexpr bool
            empty() const noexcept
            {
                return nullptr == m_data;
            }

        protected:
            //     /// <!-- description -->
            ///   @brief Destroyes a previously created bsl::view
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            ~view() noexcept = default;

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
            constexpr view(view const &o) noexcept = default;

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
            constexpr view(view &&o) noexcept = default;

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
            [[maybe_unused]] constexpr view &    // --
            operator=(view const &o) &noexcept = default;

            /// <!-- description -->
            ///   @brief move assignment
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being moved
            ///   @return a reference to *this
            ///
            [[maybe_unused]] constexpr view &    // --
            operator=(view &&o) &noexcept = default;
        };
    }

    /// <!-- description -->
    ///   @brief Loops through the array, and for each element in the view,
    ///     calls the provided function "f" with a reference to the view
    ///     element as well as the index of the element. Note that this version
    ///     loops through the view from 0 to N - 1.
    ///
    ///   SUPPRESSION: PRQA 2023 - exception required
    ///   - We suppress this because A13-3-1 states that you should not
    ///     overload functions that contain a forwarding reference because
    ///     it is confusing to the user. In this case, there is nothing
    ///     ambiguous about this situation as we are not overloading the
    ///     forewarding reference itself, which is the only way to define a
    ///     function pointer that accepts lambdas with capture lists.
    ///     The examples that demonstrate a problem overload the forwarding
    ///     reference itself, which is what creates the ambiguity.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the array's element type
    ///   @tparam FUNC The type the defines the function "f"
    ///   @param v the view to loop over
    ///   @param f the function f to call
    ///
    template<typename T, typename FUNC>
    constexpr void
    for_each(details::view<T> &v, FUNC &&f)    // PRQA S 2023 // NOLINT
        noexcept(is_nothrow_invocable<FUNC, T &, bsl::uintmax>::value)
    {
        static_assert(is_invocable<FUNC, T &, bsl::uintmax>::value);

        for (bsl::uintmax i{}; i < v.size(); ++i) {
            invoke(bsl::forward<FUNC>(f), *v.at_if(i), i);
        }
    }

    /// <!-- description -->
    ///   @brief Loops through the array, and for each element in the view,
    ///     calls the provided function "f" with a reference to the view
    ///     element as well as the index of the element. Note that this version
    ///     loops through the view from 0 to N - 1.
    ///
    ///   SUPPRESSION: PRQA 2023 - exception required
    ///   - We suppress this because A13-3-1 states that you should not
    ///     overload functions that contain a forwarding reference because
    ///     it is confusing to the user. In this case, there is nothing
    ///     ambiguous about this situation as we are not overloading the
    ///     forewarding reference itself, which is the only way to define a
    ///     function pointer that accepts lambdas with capture lists.
    ///     The examples that demonstrate a problem overload the forwarding
    ///     reference itself, which is what creates the ambiguity.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the array's element type
    ///   @tparam FUNC The type the defines the function "f"
    ///   @param v the view to loop over
    ///   @param pos the stating position of the loop
    ///   @param f the function f to call
    ///
    template<typename T, typename FUNC>
    constexpr void
    for_each(details::view<T> &v, bsl::uintmax const pos, FUNC &&f)    // PRQA S 2023 // NOLINT
        noexcept(is_nothrow_invocable<FUNC, T &, bsl::uintmax>::value)
    {
        static_assert(is_invocable<FUNC, T &, bsl::uintmax>::value);

        for (bsl::uintmax i{pos}; i < v.size(); ++i) {
            invoke(bsl::forward<FUNC>(f), *v.at_if(i), i);
        }
    }

    /// <!-- description -->
    ///   @brief Loops through the array, and for each element in the view,
    ///     calls the provided function "f" with a reference to the view
    ///     element as well as the index of the element. Note that this version
    ///     loops through the view from 0 to N - 1.
    ///
    ///   SUPPRESSION: PRQA 2023 - exception required
    ///   - We suppress this because A13-3-1 states that you should not
    ///     overload functions that contain a forwarding reference because
    ///     it is confusing to the user. In this case, there is nothing
    ///     ambiguous about this situation as we are not overloading the
    ///     forewarding reference itself, which is the only way to define a
    ///     function pointer that accepts lambdas with capture lists.
    ///     The examples that demonstrate a problem overload the forwarding
    ///     reference itself, which is what creates the ambiguity.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the array's element type
    ///   @tparam FUNC The type the defines the function "f"
    ///   @param v the view to loop over
    ///   @param pos the stating position of the loop
    ///   @param count the number of iterations to make make in the loop
    ///   @param f the function f to call
    ///
    template<typename T, typename FUNC>
    constexpr void
    for_each(                        // PRQA S 2023 // NOLINT
        details::view<T> &v,         // --
        bsl::uintmax const pos,      // --
        bsl::uintmax const count,    // --
        FUNC &&f) noexcept(is_nothrow_invocable<FUNC, T &, bsl::uintmax>::value)
    {
        static_assert(is_invocable<FUNC, T &, bsl::uintmax>::value);

        if (pos >= v.size()) {
            return;
        }

        if (count > v.size() - pos) {
            return;
        }

        for (bsl::uintmax i{pos}; i < pos + count; ++i) {
            invoke(bsl::forward<FUNC>(f), *v.at_if(i), i);
        }
    }

    /// <!-- description -->
    ///   @brief Loops through the array, and for each element in the view,
    ///     calls the provided function "f" with a reference to the view
    ///     element as well as the index of the element. Note that this version
    ///     loops through the view from 0 to N - 1.
    ///
    ///   SUPPRESSION: PRQA 2023 - exception required
    ///   - We suppress this because A13-3-1 states that you should not
    ///     overload functions that contain a forwarding reference because
    ///     it is confusing to the user. In this case, there is nothing
    ///     ambiguous about this situation as we are not overloading the
    ///     forewarding reference itself, which is the only way to define a
    ///     function pointer that accepts lambdas with capture lists.
    ///     The examples that demonstrate a problem overload the forwarding
    ///     reference itself, which is what creates the ambiguity.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the array's element type
    ///   @tparam FUNC The type the defines the function "f"
    ///   @param v the view to loop over
    ///   @param f the function f to call
    ///
    template<typename T, typename FUNC>
    constexpr void
    for_each(details::view<T> const &v, FUNC &&f)    // PRQA S 2023 // NOLINT
        noexcept(is_nothrow_invocable<FUNC, T &, bsl::uintmax>::value)
    {
        static_assert(is_invocable<FUNC, T &, bsl::uintmax>::value);

        for (bsl::uintmax i{}; i < v.size(); ++i) {
            invoke(bsl::forward<FUNC>(f), *v.at_if(i), i);
        }
    }

    /// <!-- description -->
    ///   @brief Loops through the array, and for each element in the view,
    ///     calls the provided function "f" with a reference to the view
    ///     element as well as the index of the element. Note that this version
    ///     loops through the view from 0 to N - 1.
    ///
    ///   SUPPRESSION: PRQA 2023 - exception required
    ///   - We suppress this because A13-3-1 states that you should not
    ///     overload functions that contain a forwarding reference because
    ///     it is confusing to the user. In this case, there is nothing
    ///     ambiguous about this situation as we are not overloading the
    ///     forewarding reference itself, which is the only way to define a
    ///     function pointer that accepts lambdas with capture lists.
    ///     The examples that demonstrate a problem overload the forwarding
    ///     reference itself, which is what creates the ambiguity.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the array's element type
    ///   @tparam FUNC The type the defines the function "f"
    ///   @param v the view to loop over
    ///   @param pos the stating position of the loop
    ///   @param f the function f to call
    ///
    template<typename T, typename FUNC>
    constexpr void
    for_each(
        details::view<T> const &v, bsl::uintmax const pos, FUNC &&f)    // PRQA S 2023 // NOLINT
        noexcept(is_nothrow_invocable<FUNC, T &, bsl::uintmax>::value)
    {
        static_assert(is_invocable<FUNC, T &, bsl::uintmax>::value);

        for (bsl::uintmax i{pos}; i < v.size(); ++i) {
            invoke(bsl::forward<FUNC>(f), *v.at_if(i), i);
        }
    }

    /// <!-- description -->
    ///   @brief Loops through the array, and for each element in the view,
    ///     calls the provided function "f" with a reference to the view
    ///     element as well as the index of the element. Note that this version
    ///     loops through the view from 0 to N - 1.
    ///
    ///   SUPPRESSION: PRQA 2023 - exception required
    ///   - We suppress this because A13-3-1 states that you should not
    ///     overload functions that contain a forwarding reference because
    ///     it is confusing to the user. In this case, there is nothing
    ///     ambiguous about this situation as we are not overloading the
    ///     forewarding reference itself, which is the only way to define a
    ///     function pointer that accepts lambdas with capture lists.
    ///     The examples that demonstrate a problem overload the forwarding
    ///     reference itself, which is what creates the ambiguity.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the array's element type
    ///   @tparam FUNC The type the defines the function "f"
    ///   @param v the view to loop over
    ///   @param pos the stating position of the loop
    ///   @param count the number of iterations to make make in the loop
    ///   @param f the function f to call
    ///
    template<typename T, typename FUNC>
    constexpr void
    for_each(                         // PRQA S 2023 // NOLINT
        details::view<T> const &v,    // --
        bsl::uintmax const pos,       // --
        bsl::uintmax const count,     // --
        FUNC &&f) noexcept(is_nothrow_invocable<FUNC, T &, bsl::uintmax>::value)
    {
        static_assert(is_invocable<FUNC, T &, bsl::uintmax>::value);

        if (pos >= v.size()) {
            return;
        }

        if (count > v.size() - pos) {
            return;
        }

        for (bsl::uintmax i{pos}; i < pos + count; ++i) {
            invoke(bsl::forward<FUNC>(f), *v.at_if(i), i);
        }
    }
}

#endif
