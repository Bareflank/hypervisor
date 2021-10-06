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

#ifndef BASIC_PAGE_POOL_T_HPP
#define BASIC_PAGE_POOL_T_HPP

#if __has_include("page_pool_helpers.hpp")
#include <page_pool_helpers.hpp>    // IWYU pragma: export
#endif

#if __has_include("basic_page_pool_helpers.hpp")
#include <basic_page_pool_helpers.hpp>    // IWYU pragma: export
#endif

// IWYU pragma: no_include "page_pool_helpers.hpp"
// IWYU pragma: no_include "basic_page_pool_helpers.hpp"
// IWYU pragma: no_include "basic_page_pool_node_t.hpp"

#include <basic_lock_guard_t.hpp>        // IWYU pragma: keep
#include <basic_page_pool_node_t.hpp>    // IWYU pragma: export
#include <basic_spinlock_t.hpp>          // IWYU pragma: keep

#include <bsl/construct_at.hpp>
#include <bsl/convert.hpp>
#include <bsl/cstring.hpp>
#include <bsl/debug.hpp>
#include <bsl/destroy_at.hpp>
#include <bsl/dontcare_t.hpp>
#include <bsl/ensures.hpp>
#include <bsl/expects.hpp>
#include <bsl/is_pod.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/span.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace lib
{
    /// <!-- description -->
    ///   @brief the basic_page_pool_t is responsible for allocating and freeing
    ///      pages. The loader provides a linked list with the pages that
    ///      this code will allocate as requested. Each page exists in the
    ///      direct map, so all virt to phys translations of allocated pages
    ///      can be done using simple arithmetic.
    ///
    /// <!-- template parameters -->
    ///   @tparam TLS_TYPE the type of TLS block to use
    ///   @tparam SYS_TYPE the type of bf_syscall_t to use
    ///   @tparam MAP_ADDR the starting address of the address space
    ///   @tparam MAP_SIZE the max size of the address space
    ///
    template<typename TLS_TYPE, typename SYS_TYPE, bsl::uintmx MAP_ADDR, bsl::uintmx MAP_SIZE>
    class basic_page_pool_t final
    {
        /// @brief stores the head of the basic_page_pool_t.
        basic_page_pool_node_t *m_head{};
        /// @brief stores the total number of bytes given to the basic_page_pool_t.
        bsl::safe_umx m_size{};
        /// @brief stores the total number of bytes given to the basic_page_pool_t.
        bsl::safe_umx m_used{};
        /// @brief safe guards operations on the pool.
        mutable basic_spinlock_t m_lock{};

        /// <!-- description -->
        ///   @brief Converts a virtual address to a physical address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param virt the virtual address to convert
        ///   @return the resulting physical address
        ///
        [[nodiscard]] constexpr auto
        virt_to_phys(bsl::safe_umx const &virt) const noexcept -> bsl::safe_umx
        {
            constexpr bsl::safe_umx min_addr{MAP_ADDR};
            constexpr bsl::safe_umx max_addr{(min_addr + MAP_SIZE).checked()};

            bsl::expects(virt.is_valid_and_checked());
            bsl::expects(virt.is_pos());
            bsl::expects(virt > min_addr);
            bsl::expects(virt < max_addr);

            return (virt - min_addr).checked();
        }

        /// <!-- description -->
        ///   @brief Converts a physical address to a virtual address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param phys the physical address to convert
        ///   @return the resulting virtual address
        ///
        [[nodiscard]] constexpr auto
        phys_to_virt(bsl::safe_umx const &phys) const noexcept -> bsl::safe_umx
        {
            bsl::expects(phys.is_valid_and_checked());
            bsl::expects(phys.is_pos());
            bsl::expects(phys < MAP_SIZE);

            return (phys + MAP_ADDR).checked();
        }

        /// <!-- description -->
        ///   @brief Returns the number of bytes allocated.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the number of bytes allocated.
        ///
        [[nodiscard]] constexpr auto
        allocated() const noexcept -> bsl::safe_umx
        {
            /// NOTE:
            /// - The following is marked checked because the allocation
            ///   function ensures this math will never overflow.
            ///

            return m_used.checked();
        }

        /// <!-- description -->
        ///   @brief Returns this->size() - this->allocated().
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns this->size() - this->allocated().
        ///
        [[nodiscard]] constexpr auto
        remaining() const noexcept -> bsl::safe_umx
        {
            /// NOTE:
            /// - The following is marked checked because the allocation
            ///   function ensures this math will never overflow.
            ///

            return (this->size() - this->allocated()).checked();
        }

    public:
        /// <!-- description -->
        ///   @brief Creates the basic_page_pool_t given a mutable_buffer_t to
        ///     the basic_page_pool_t as well as the virtual address base of the
        ///     page pool which is used for virt to phys translations.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_pool the mutable_buffer_t of the basic_page_pool_t
        ///
        constexpr void
        initialize(bsl::span<basic_page_pool_node_t> &mut_pool) noexcept
        {
            m_head = mut_pool.data();
            m_size = (mut_pool.size() * HYPERVISOR_PAGE_SIZE).checked();
            m_used = {};
        }

        /// <!-- description -->
        ///   @brief Allocates a page from the basic_page_pool_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of pointer to allocate
        ///   @param tls the current TLS block
        ///   @param mut_sys the bf_syscall_t to use
        ///   @return Returns a pointer to the newly allocated page
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        allocate(TLS_TYPE const &tls, SYS_TYPE &mut_sys = bsl::dontcare) noexcept -> T *
        {
            static_assert(bsl::is_pod<T>::value);
            static_assert(sizeof(T) == HYPERVISOR_PAGE_SIZE);

            basic_lock_guard_t mut_lock{tls, m_lock};

            if (bsl::unlikely(nullptr == m_head)) {
                m_head = helpers::add_to_page_pool(mut_sys);
                if (bsl::unlikely(nullptr == m_head)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return {};
                }

                m_size += HYPERVISOR_PAGE_SIZE;
            }
            else {
                bsl::touch();
            }

            auto *const pmut_node{m_head};
            m_head = m_head->next;
            m_used += HYPERVISOR_PAGE_SIZE;

            /// NOTE:
            /// - Since we only support POD types, we have two options on
            ///   how to produce a type T *:
            ///   - We could static cast to a void * and then from the
            ///     void * to a type T *.
            ///   - We could use placement new.
            ///
            /// - Although placement new is overkill because we have a POD
            ///   type, it is technically the more appropriate way to handle
            ///   lifetime management, so that is what we do here. To do that
            ///   we treat the memory as if it were a union by destroying the
            ///   node and then creating our type T.
            ///

            bsl::destroy_at(pmut_node);
            auto *const pmut_virt{bsl::construct_at<T>(pmut_node)};

            return bsl::builtin_memset(pmut_virt, '\0', HYPERVISOR_PAGE_SIZE);
        }

        /// <!-- description -->
        ///   @brief Returns a page previously allocated using the allocate
        ///     function to the basic_page_pool_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of pointer to deallocate
        ///   @param tls the current TLS block
        ///   @param pmut_virt the pointer to the page to deallocate
        ///
        template<typename T>
        constexpr void
        deallocate(TLS_TYPE const &tls, T *const pmut_virt) noexcept
        {
            static_assert(bsl::is_pod<T>::value);
            static_assert(sizeof(T) == HYPERVISOR_PAGE_SIZE);

            bsl::expects(nullptr != pmut_virt);
            basic_lock_guard_t mut_lock{tls, m_lock};

            /// NOTE:
            /// - To deallocate, we simply do the reverse, again treating
            ///   the node as a union. First we destroy the type T * that we
            ///   were given and then create our node using placement new.
            ///

            bsl::destroy_at(pmut_virt);
            auto *const pmut_node{bsl::construct_at<basic_page_pool_node_t>(pmut_virt)};

            pmut_node->next = m_head;
            m_head = pmut_node;
            m_used -= HYPERVISOR_PAGE_SIZE;
        }

        /// <!-- description -->
        ///   @brief Returns the number of bytes in the pool.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the number of bytes in the pool.
        ///
        [[nodiscard]] constexpr auto
        size() const noexcept -> bsl::safe_umx
        {
            bsl::ensures(m_size.is_valid_and_checked());
            return m_size;
        }

        /// <!-- description -->
        ///   @brief Returns the number of bytes allocated.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @return Returns the number of bytes allocated.
        ///
        [[nodiscard]] constexpr auto
        allocated(TLS_TYPE const &tls) const noexcept -> bsl::safe_umx
        {
            basic_lock_guard_t mut_lock{tls, m_lock};
            return this->allocated();
        }

        /// <!-- description -->
        ///   @brief Returns this->size() - this->allocated().
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @return Returns this->size() - this->allocated().
        ///
        [[nodiscard]] constexpr auto
        remaining(TLS_TYPE const &tls) const noexcept -> bsl::safe_umx
        {
            basic_lock_guard_t mut_lock{tls, m_lock};
            return this->remaining();
        }

        /// <!-- description -->
        ///   @brief Converts a virtual address to a physical address.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T defines the type of virtual address being converted
        ///   @param virt the virtual address to convert
        ///   @return the resulting physical address
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        virt_to_phys(T const *const virt) const noexcept -> bsl::safe_umx
        {
            static_assert(bsl::is_pod<T>::value);
            static_assert(sizeof(T) == HYPERVISOR_PAGE_SIZE);

            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            return this->virt_to_phys(bsl::to_umx(reinterpret_cast<bsl::uintmx>(virt)));
        }

        /// <!-- description -->
        ///   @brief Converts a physical address to a virtual address.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T defines the type of virtual address to convert to
        ///   @param phys the physical address to convert
        ///   @return the resulting virtual address
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        phys_to_virt(bsl::safe_umx const &phys) const noexcept -> T *
        {
            static_assert(bsl::is_pod<T>::value);
            static_assert(sizeof(T) == HYPERVISOR_PAGE_SIZE);

            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            return reinterpret_cast<T *>(this->phys_to_virt(phys).get());
        }

        /// <!-- description -->
        ///   @brief Dumps the basic_page_pool_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///
        constexpr void
        dump(TLS_TYPE const &tls) const noexcept
        {
            basic_lock_guard_t mut_lock{tls, m_lock};

            constexpr auto kb{1024_umx};
            constexpr auto mb{kb * kb};

            bsl::print() << bsl::mag << "page pool dump: ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Header
            ///

            bsl::print() << bsl::ylw << "+----------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::blu << bsl::fmt{"^33s", "overview "};
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            bsl::print() << bsl::ylw << "+----------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::cyn << bsl::fmt{"^23s", "description "};
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::cyn << bsl::fmt{"^8s", "value "};
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            bsl::print() << bsl::ylw << "+----------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            /// Total
            ///

            auto const total_kb{(this->size() / kb).checked()};
            auto const total_mb{(this->size() / mb).checked()};

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<23s", "total "};
            bsl::print() << bsl::ylw << "| ";
            if (total_mb.is_zero()) {
                bsl::print() << bsl::rst << bsl::fmt{"4d", total_kb} << " KB ";
            }
            else {
                bsl::print() << bsl::rst << bsl::fmt{"4d", total_mb} << " MB ";
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Used
            ///

            auto const used_kb{(this->allocated() / kb).checked()};
            auto const used_mb{(this->allocated() / mb).checked()};

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<23s", "used "};
            bsl::print() << bsl::ylw << "| ";
            if (used_mb.is_zero()) {
                bsl::print() << bsl::rst << bsl::fmt{"4d", used_kb} << " KB ";
            }
            else {
                bsl::print() << bsl::rst << bsl::fmt{"4d", used_mb} << " MB ";
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Remaining
            ///

            auto const remaining_kb{(this->remaining() / kb).checked()};
            auto const remaining_mb{(this->remaining() / mb).checked()};

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<23s", "remaining "};
            bsl::print() << bsl::ylw << "| ";
            if (remaining_mb.checked().is_zero()) {
                bsl::print() << bsl::rst << bsl::fmt{"4d", remaining_kb} << " KB ";
            }
            else {
                bsl::print() << bsl::rst << bsl::fmt{"4d", remaining_mb} << " MB ";
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Footer
            ///

            bsl::print() << bsl::ylw << "+----------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;
        }
    };
}

#endif
