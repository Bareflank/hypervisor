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

#ifndef PAGE_POOL_T_HPP
#define PAGE_POOL_T_HPP

#include <lock_guard_t.hpp>
#include <page_pool_node_t.hpp>
#include <page_pool_record_t.hpp>
#include <spinlock_t.hpp>
#include <tls_t.hpp>

#include <bsl/array.hpp>
#include <bsl/construct_at.hpp>
#include <bsl/convert.hpp>
#include <bsl/cstring.hpp>
#include <bsl/debug.hpp>
#include <bsl/destroy_at.hpp>
#include <bsl/is_trivial.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/span.hpp>
#include <bsl/string_view.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// @brief stores the max number of records the page pool can store
    constexpr auto PAGE_POOL_MAX_RECORDS{9_umax};

    /// @class mk::page_pool_t
    ///
    /// <!-- description -->
    ///   @brief The page pool is responsible for allocating and freeing
    ///      pages. The loader provides a linked list with the pages that
    ///      this code will allocate as requested. Each page exists in the
    ///      direct map, so all virt to phys translations of allocated pages
    ///      can be done using simple arithmetic.
    ///
    class page_pool_t final
    {
        /// @brief stores the head of the page pool.
        loader::page_pool_node_t *m_head{};
        /// @brief stores the total number of bytes given to the page pool.
        bsl::safe_uintmax m_size{};
        /// @brief stores information about how memory is allocated
        bsl::array<page_pool_record_t, PAGE_POOL_MAX_RECORDS.get()> m_rcds{};
        /// @brief safe guards operations on the pool.
        mutable spinlock_t m_lock{};

    public:
        /// <!-- description -->
        ///   @brief Creates the page pool given a mutable_buffer_t to
        ///     the page pool as well as the virtual address base of the
        ///     page pool which is used for virt to phys translations.
        ///
        /// <!-- inputs/outputs -->
        ///   @param pool the mutable_buffer_t of the page pool
        ///
        constexpr void
        initialize(bsl::span<loader::page_pool_node_t> &pool) noexcept
        {
            m_head = pool.data();
            m_size = pool.size() * HYPERVISOR_PAGE_SIZE;
        }

        /// <!-- description -->
        ///   @brief Allocates a page from the page pool.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of pointer to allocate
        ///   @param tls the current TLS block
        ///   @param tag the tag to mark the allocation with
        ///   @return Returns a pointer to the newly allocated page
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        allocate(tls_t &tls, bsl::string_view const &tag) noexcept -> T *
        {
            static_assert(sizeof(T) == HYPERVISOR_PAGE_SIZE);
            lock_guard_t lock{tls, m_lock};

            if (tag.empty()) {
                bsl::error() << "invalid empty tag"    // --
                             << bsl::endl              // --
                             << bsl::here();           // --

                return nullptr;
            }

            if (bsl::unlikely(nullptr == m_head)) {
                bsl::error() << "page pool out of pages\n" << bsl::here();
                return nullptr;
            }

            page_pool_record_t *record{};
            for (auto const elem : m_rcds) {
                if (nullptr == elem.data->tag) {
                    record = elem.data;
                    record->tag = tag.data();
                    break;
                }

                if (tag == elem.data->tag) {
                    record = elem.data;
                    break;
                }

                bsl::touch();
            }

            if (nullptr == record) {
                bsl::error() << "page pool out of space for tags\n" << bsl::here();
                return nullptr;
            }

            auto *const node{m_head};
            m_head = m_head->next;
            record->usd += HYPERVISOR_PAGE_SIZE;

            /// NOTE:
            /// - We need start the lifetime of the object we are allocating.
            ///   To do this, we first need to end the lifetime of the node
            ///   itself, which is done using destroy_at.
            /// - Next, we need to construct T. This starts the lifetime of
            ///   T at the address provided by the node. In other words, we
            ///   now a pointer of type T that has been properly constructed.
            /// - Finally, if the type is trivial, we zero the memory of the
            ///   type. This ensures that all trivial types are properly
            ///   constructed and cleared as there is no default constructor
            ///   to initialize the type.
            ///

            bsl::destroy_at(node);
            auto *const ptr{bsl::construct_at<T>(node)};

            if (bsl::is_trivial<T>::value) {
                return bsl::builtin_memset(ptr, '\0', HYPERVISOR_PAGE_SIZE);
            }

            return ptr;
        }

        /// <!-- description -->
        ///   @brief Returns a page previously allocated using the allocate
        ///     function to the page pool.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of pointer to deallocate
        ///   @param tls the current TLS block
        ///   @param ptr the pointer to the page to deallocate
        ///   @param tag the tag the allocation was marked with
        ///
        template<typename T>
        constexpr void
        deallocate(tls_t &tls, T *const ptr, bsl::string_view const &tag) noexcept
        {
            static_assert(sizeof(T) == HYPERVISOR_PAGE_SIZE);
            lock_guard_t lock{tls, m_lock};

            if (bsl::unlikely(nullptr == ptr)) {
                return;
            }

            page_pool_record_t *record{};
            for (auto const elem : m_rcds) {
                if (elem.data->tag == tag) {
                    record = elem.data;
                    break;
                }

                bsl::touch();
            }

            if (nullptr == record) {
                bsl::error() << "invalid tag "    // --
                             << tag               // --
                             << bsl::endl         // --
                             << bsl::here();      // --

                return;
            }

            /// NOTE:
            /// - We are given a T *. This should be the same T * that we
            ///   returned from the allocator. T * is not a node, unless this
            ///   is the unit test. Before we can use T * as a node, we need
            ///   to construct T * as a node, the same way that we constructed
            ///   the T * in the first place. To do that, we must first end
            ///   the lifetime of the provided T *.
            /// - Next, we construct a node using the memory from T *. This
            ///   beings the lifetime of our node.
            /// - Finally, we add the node to the linked list.
            /// - You might be wondering why we simply do not use a static_cast.
            ///   If the types are POD types, a static_cast using void * would
            ///   be enough without invoking undefined behavior. The use of
            ///   void * in a constexpr is not allowed however. To overcome
            ///   this, we properly handle the lifetime of the objects that
            ///   we are using. The unit test only ever sees nodes, so to the
            ///   unit test, the page allocator looks like a linked list that
            ///   outputs nodes using a stack like process. This is enough to
            ///   ensure that the page pool never invokes UB, and is handling
            ///   the allocations properly. The runtime logic is able to change
            ///   the types from T to node without issue and without using UB.
            ///   No reinterpret_cast is ever needed to make this work. The
            ///   rest of the code that uses the page pool during unit testing
            ///   will use a mocked version of the page pool that uses new and
            ///   delete to properly create a constexpr friendly version of T.
            ///

            bsl::destroy_at(ptr);
            auto *const node{bsl::construct_at<loader::page_pool_node_t>(ptr)};

            node->next = m_head;
            m_head = node;
            record->usd -= HYPERVISOR_PAGE_SIZE;
        }

        /// <!-- description -->
        ///   @brief Returns the number of bytes allocated for a given tag.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param tag the tag the allocation was marked with
        ///   @return Returns the number of bytes allocated for a given tag.
        ///
        [[nodiscard]] constexpr auto
        allocated(tls_t &tls, bsl::string_view const &tag) noexcept -> bsl::safe_uintmax
        {
            lock_guard_t lock{tls, m_lock};

            for (auto const elem : m_rcds) {
                if (elem.data->tag == tag) {
                    return elem.data->usd;
                }

                bsl::touch();
            }

            bsl::error() << "invalid tag "    // --
                         << tag               // --
                         << bsl::endl         // --
                         << bsl::here();      // --

            return bsl::safe_uintmax::failure();
        }

        /// <!-- description -->
        ///   @brief Converts a virtual address to a physical address for
        ///     any page allocated by the page pool. If the provided ptr
        ///     was not allocated using the allocate function by the same
        ///     page pool, this results of this function are UB. It should
        ///     be noted that any virtual address may be used meaning the
        ///     provided address does not have to be page aligned, it simply
        ///     needs to be allocated using the same page pool.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T defines the type of virtual address being converted
        ///   @param virt the virtual address to convert
        ///   @return the resulting physical address
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        virt_to_phys(T const *const virt) const noexcept -> bsl::safe_uintmax
        {
            static_assert(sizeof(T) == HYPERVISOR_PAGE_SIZE);
            return bsl::to_umax(virt) - HYPERVISOR_MK_PAGE_POOL_ADDR;
        }

        /// <!-- description -->
        ///   @brief Converts a physical address to a virtual address for
        ///     any page allocated by the page pool. If the provided address
        ///     was not allocated using the allocate function by the same
        ///     page pool, this results of this function are UB. It should
        ///     be noted that any physical address may be used meaning the
        ///     provided address does not have to be page aligned, it simply
        ///     needs to be allocated using the same page pool.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T defines the type of virtual address to convert to
        ///   @param phys the physical address to convert
        ///   @return the resulting virtual address
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        phys_to_virt(bsl::safe_uintmax const &phys) const noexcept -> T *
        {
            static_assert(sizeof(T) == HYPERVISOR_PAGE_SIZE);
            return bsl::to_ptr<T *>(phys + HYPERVISOR_MK_PAGE_POOL_ADDR);
        }

        /// <!-- description -->
        ///   @brief Dumps the page_pool_t
        ///
        constexpr void
        dump() const noexcept
        {
            constexpr auto kb{1024_umax};
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

            bsl::safe_uintmax usd{};
            for (auto const elem : m_rcds) {
                usd += elem.data->usd;
            }

            /// Total
            ///

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<23s", "total "};
            bsl::print() << bsl::ylw << "| ";
            if ((m_size / mb).is_zero()) {
                bsl::print() << bsl::rst << bsl::fmt{"4d", m_size / kb} << " KB ";
            }
            else {
                bsl::print() << bsl::rst << bsl::fmt{"4d", m_size / mb} << " MB ";
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Used
            ///

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<23s", "used "};
            bsl::print() << bsl::ylw << "| ";
            if ((usd / mb).is_zero()) {
                bsl::print() << bsl::rst << bsl::fmt{"4d", usd / kb} << " KB ";
            }
            else {
                bsl::print() << bsl::rst << bsl::fmt{"4d", usd / mb} << " MB ";
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Remaining
            ///

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<23s", "remaining "};
            bsl::print() << bsl::ylw << "| ";
            if (((m_size - usd) / mb).is_zero()) {
                bsl::print() << bsl::rst << bsl::fmt{"4d", (m_size - usd) / kb} << " KB ";
            }
            else {
                bsl::print() << bsl::rst << bsl::fmt{"4d", (m_size - usd) / mb} << " MB ";
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Tags
            ///

            bsl::print() << bsl::ylw << "+----------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            bsl::print() << bsl::rst << bsl::endl;
            bsl::print() << bsl::ylw << "+----------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::blu << bsl::fmt{"^33s", "breakdown "};
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

            for (auto const elem : m_rcds) {
                if (nullptr == elem.data->tag) {
                    continue;
                }

                bsl::print() << bsl::ylw << "| ";
                bsl::print() << bsl::rst << bsl::fmt{"<23s", elem.data->tag};
                bsl::print() << bsl::ylw << "| ";
                if ((elem.data->usd / mb).is_zero()) {
                    bsl::print() << bsl::rst << bsl::fmt{"4d", elem.data->usd / kb} << " KB ";
                }
                else {
                    bsl::print() << bsl::rst << bsl::fmt{"4d", elem.data->usd / mb} << " MB ";
                }
                bsl::print() << bsl::ylw << "| ";
                bsl::print() << bsl::rst << bsl::endl;
            }

            /// Footer
            ///

            bsl::print() << bsl::ylw << "+----------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;
        }
    };
}

#endif
