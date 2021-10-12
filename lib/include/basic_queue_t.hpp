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

#ifndef BASIC_QUEUE_T_HPP
#define BASIC_QUEUE_T_HPP

#include <bsl/array.hpp>
#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace lib
{
    /// <!-- description -->
    ///   @brief Provides a simple queue using a static array. Unlike most
    ///     queues that use dynamic memory, this queue has a fixed size, and
    ///     once this fixed size is full, attempting to push to the queue
    ///     will fail.
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type of element being encapsulated.
    ///   @tparam N the total number of elements in the array. Cannot be 0
    ///
    template<typename T, bsl::uintmx N>
    class basic_queue_t final
    {
        /// @brief stores a circular buffer for the queue.
        bsl::array<T, N> m_queue{};
        /// @brief stores the head of the queue.
        bsl::safe_idx m_head{};
        /// @brief stores the tail of the queue.
        bsl::safe_idx m_tail{};

    public:
        /// @brief alias for: T
        using value_type = T;
        /// @brief alias for: safe_umx
        using size_type = bsl::safe_umx;
        /// @brief alias for: safe_idx
        using index_type = bsl::safe_idx;
        /// @brief alias for: safe_umx
        using difference_type = bsl::safe_umx;
        /// @brief alias for: T &
        using reference_type = T &;
        /// @brief alias for: T const &
        using const_reference_type = T const &;
        /// @brief alias for: T *
        using pointer_type = T *;
        /// @brief alias for: T const *
        using const_pointer_type = T const *;

        /// <!-- description -->
        ///   @brief Pushes an element to the queue and returns
        ///     bsl::errc_success. If the queue is full, returns
        ///     bsl::errc_failure.
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to push to the queue
        ///   @param sloc the source location of the push for debugging
        ///   @return Returns bsl::errc_success on success, or
        ///     bsl::errc_failure if the queue is full.
        ///
        [[nodiscard]] constexpr auto
        push(T const &val, bsl::source_location const &sloc = bsl::here()) noexcept
            -> bsl::errc_type
        {
            if (bsl::unlikely(this->full())) {
                bsl::error() << "queue is full\n" << sloc;
                return bsl::errc_failure;
            }

            *m_queue.at_if(m_head) = val;

            ++m_head;
            if (m_head >= N) {
                m_head = {};
            }
            else {
                bsl::touch();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Pops an element from the queue and returns
        ///     bsl::errc_success. If the queue is empty, returns
        ///     bsl::errc_failure.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_val where to return the popped element
        ///   @param sloc the source location of the pop for debugging
        ///   @return Returns bsl::errc_success on success, or
        ///     bsl::errc_failure if the queue is full.
        ///
        [[nodiscard]] constexpr auto
        pop(T &mut_val, bsl::source_location const &sloc = bsl::here()) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely(this->empty())) {
                bsl::error() << "queue is empty\n" << sloc;
                return bsl::errc_failure;
            }

            mut_val = *m_queue.at_if(m_tail);

            ++m_tail;
            if (m_tail >= N) {
                m_tail = {};
            }
            else {
                bsl::touch();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns true if the queue is empty. Returns false
        ///     otherwise.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the queue is empty. Returns false
        ///     otherwise.
        ///
        [[nodiscard]] constexpr auto
        empty() const noexcept -> bool
        {
            return m_head == m_tail;
        }

        /// <!-- description -->
        ///   @brief Returns true if the queue is empty. Returns false
        ///     otherwise.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the queue is empty. Returns false
        ///     otherwise.
        ///
        [[nodiscard]] constexpr auto
        full() const noexcept -> bool
        {
            auto next_head{m_head + bsl::safe_idx::magic_1()};
            if (next_head >= N) {
                return m_tail.is_zero();
            }

            return next_head == m_tail;
        }

        /// <!-- description -->
        ///   @brief Returns the number of elements in the queue
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the number of elements in the queue
        ///
        [[nodiscard]] static constexpr auto
        size() noexcept -> size_type
        {
            // ensures(N.is_valid_and_checked());
            return size_type{N};
        }
    };
}

#endif
