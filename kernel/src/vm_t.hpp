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

#ifndef VM_T_HPP
#define VM_T_HPP

#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/finally.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// @brief defines the value of an invalid VMID
    constexpr bsl::safe_uint16 INVALID_VMID{bsl::to_u16(0xFFFFU)};

    /// @class mk::vm_t
    ///
    /// <!-- description -->
    ///   @brief TODO
    ///
    /// <!-- template parameters -->
    ///   @tparam PAGE_POOL_CONCEPT defines the type of page pool to use
    ///
    template<typename PAGE_POOL_CONCEPT>
    class vm_t final
    {
        /// @brief stores true if initialized() has been executed
        bool m_initialized{};
        /// @brief stores a reference to the page pool to use
        PAGE_POOL_CONCEPT *m_page_pool{};
        /// @brief stores the ID associated with this vm_t
        bsl::safe_uint16 m_id{bsl::safe_uint16::zero(true)};
        /// @brief stores the next vm_t in the vm_pool_t linked list
        vm_t *m_next{};

    public:
        /// @brief an alias for PAGE_POOL_CONCEPT
        using page_pool_type = PAGE_POOL_CONCEPT;

        /// <!-- description -->
        ///   @brief Default constructor
        ///
        constexpr vm_t() noexcept = default;

        /// <!-- description -->
        ///   @brief Initializes this vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param page_pool the page pool to use
        ///   @param i the ID for this vm_t
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(PAGE_POOL_CONCEPT *const page_pool, bsl::safe_uint16 const &i) &noexcept
            -> bsl::errc_type
        {
            if (bsl::unlikely(m_initialized)) {
                bsl::error() << "vm_t already initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            bsl::finally release_on_error{[this]() noexcept -> void {
                this->release();
            }};

            m_page_pool = page_pool;
            if (bsl::unlikely(nullptr == m_page_pool)) {
                bsl::error() << "invalid page_pool\n" << bsl::here();
                return bsl::errc_failure;
            }

            m_id = i;
            if (bsl::unlikely(!i)) {
                bsl::error() << "invalid id\n" << bsl::here();
                return bsl::errc_failure;
            }

            release_on_error.ignore();
            m_initialized = true;

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Release the vm_t
        ///
        constexpr void
        release() &noexcept
        {
            m_next = {};
            m_id = bsl::safe_uint16::zero(true);
            m_page_pool = {};
            m_initialized = {};
        }

        /// <!-- description -->
        ///   @brief Destructor
        ///
        constexpr ~vm_t() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr vm_t(vm_t const &o) noexcept = delete;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr vm_t(vm_t &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(vm_t const &o) &noexcept -> vm_t & = delete;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(vm_t &&o) &noexcept -> vm_t & = default;

        /// <!-- description -->
        ///   @brief Returns the ID of this vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of this vm_t
        ///
        [[nodiscard]] constexpr auto
        id() const &noexcept -> bsl::safe_uint16 const &
        {
            return m_id;
        }

        /// <!-- description -->
        ///   @brief Returns the next vm_t in the vm_pool_t linked list
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the next vm_t in the vm_pool_t linked list
        ///
        [[nodiscard]] constexpr auto
        next() const &noexcept -> vm_t *
        {
            return m_next;
        }

        /// <!-- description -->
        ///   @brief Sets the next vm_t in the vm_pool_t linked list
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the next vm_t in the vm_pool_t linked list to set
        ///
        constexpr void
        set_next(vm_t *val) &noexcept
        {
            m_next = val;
        }
    };
}

#endif
