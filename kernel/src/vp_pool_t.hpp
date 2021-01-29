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

#ifndef VP_POOL_T_HPP
#define VP_POOL_T_HPP

#include <bsl/array.hpp>
#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/finally.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// @class mk::vp_pool_t
    ///
    /// <!-- description -->
    ///   @brief TODO
    ///
    /// <!-- template parameters -->
    ///   @tparam VP_CONCEPT the type of vp_t that this class manages.
    ///   @tparam PAGE_POOL_CONCEPT defines the type of page pool to use
    ///   @tparam MAX_VPS the max number of VPs supported
    ///
    template<typename VP_CONCEPT, typename PAGE_POOL_CONCEPT, bsl::uintmax MAX_VPS>
    class vp_pool_t final
    {
        /// @brief stores true if initialized() has been executed
        bool m_initialized;
        /// @brief stores a reference to the page pool to use
        PAGE_POOL_CONCEPT &m_page_pool;
        /// @brief stores the first VP_CONCEPT in the VP_CONCEPT linked list
        VP_CONCEPT *m_head;
        /// @brief stores the VP_CONCEPTs in the VP_CONCEPT linked list
        bsl::array<VP_CONCEPT, MAX_VPS> m_pool;

    public:
        /// @brief an alias for VP_CONCEPT
        using vp_type = VP_CONCEPT;
        /// @brief an alias for PAGE_POOL_CONCEPT
        using page_pool_type = PAGE_POOL_CONCEPT;

        /// <!-- description -->
        ///   @brief Creates a vp_pool_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param page_pool the page pool to use
        ///
        explicit constexpr vp_pool_t(PAGE_POOL_CONCEPT &page_pool) noexcept
            : m_initialized{}, m_page_pool{page_pool}, m_head{}, m_pool{}
        {}

        /// <!-- description -->
        ///   @brief Initializes this vp_pool_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize() &noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};

            if (bsl::unlikely(m_initialized)) {
                bsl::error() << "vp_pool_t already initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            bsl::finally release_on_error{[this]() noexcept -> void {
                this->release();
            }};

            VP_CONCEPT *prev{};
            for (auto const vp : m_pool) {
                ret = vp.data->initialize(&m_page_pool, bsl::to_u16(vp.index));
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                if (nullptr != prev) {
                    prev->set_next(vp.data);
                }
                else {
                    m_head = vp.data;
                }

                prev = vp.data;
            }

            release_on_error.ignore();
            m_initialized = true;

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Release the vp_t
        ///
        constexpr void
        release() &noexcept
        {
            for (auto const vp : m_pool) {
                vp.data->release();
            }

            m_head = {};
            m_initialized = {};
        }

        /// <!-- description -->
        ///   @brief Destroyes a previously created vp_pool_t
        ///
        constexpr ~vp_pool_t() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr vp_pool_t(vp_pool_t const &o) noexcept = delete;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr vp_pool_t(vp_pool_t &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(vp_pool_t const &o) &noexcept
            -> vp_pool_t & = delete;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(vp_pool_t &&o) &noexcept -> vp_pool_t & = default;

        /// <!-- description -->
        ///   @brief Allocates a vp from the vp pool. We set the allocated
        ///     vp_t's next() to itself, which indicates that it has been
        ///     allocated.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns ID of the newly allocated vp
        ///
        [[nodiscard]] constexpr auto
        allocate() &noexcept -> bsl::safe_uint16
        {
            if (bsl::unlikely(!m_initialized)) {
                bsl::error() << "vp_pool_t not initialized\n" << bsl::here();
                return bsl::safe_uint16::zero(true);
            }

            if (bsl::unlikely(nullptr == m_head)) {
                bsl::error() << "vp pool out of vps\n" << bsl::here();
                return bsl::safe_uint16::zero(true);
            }

            auto *const vp{m_head};
            m_head = m_head->next();

            vp->set_next(vp);
            return vp->id();
        }

        /// <!-- description -->
        ///   @brief Returns a vp previously allocated using the allocate
        ///     function to the vp pool.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid the ID of the vp to deallocate
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        deallocate(bsl::safe_uint16 const &vpid) &noexcept -> bsl::errc_type
        {
            if (bsl::unlikely(!m_initialized)) {
                bsl::error() << "vp_pool_t not initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            auto *const vp{m_pool.at_if(bsl::to_umax(vpid))};
            if (bsl::unlikely(nullptr == vp)) {
                bsl::error() << "invalid vpid: "    // --
                             << bsl::hex(vpid)      // --
                             << bsl::endl           // --
                             << bsl::here();        // --

                return bsl::errc_failure;
            }

            if (vp->next() != vp) {
                bsl::error() << "vp with id "             // --
                             << bsl::hex(vpid)            // --
                             << " was never allocated"    // --
                             << bsl::endl                 // --
                             << bsl::here();              // --

                return bsl::errc_failure;
            }

            vp->set_next(m_head);
            m_head = vp;

            return bsl::errc_success;
        }
    };
}

#endif
