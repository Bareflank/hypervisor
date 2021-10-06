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

#ifndef MOCKS_HUGE_POOL_T_HPP
#define MOCKS_HUGE_POOL_T_HPP

#include <basic_page_4k_t.hpp>
#include <page_4k_t.hpp>
#include <tls_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/expects.hpp>
#include <bsl/is_pod.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/span.hpp>
#include <bsl/unordered_map.hpp>

namespace mk
{
    /// @brief defines the max number of allocations that's supported
    constexpr auto HUGE_MAX_ALLOCATIONS{10_umx};

    /// <!-- description -->
    ///   @brief The huge pool provides access to physically contiguous
    ///     memory. The amount of memory that is available is really, really
    ///     small (likely no more than 1 MB), but some is needed for different
    ///     architectures that require it like AMD. This memory is only needed
    ///     by the extensions, and we currently do not support the ability
    ///     to free memory, so there is no need to over complicate how this
    ///     allocator works. We simply use a cursor that is always increasing.
    ///     Once you allocate all of the memory, that is it.
    ///
    class huge_pool_t final
    {
        /// @brief stores the total number of bytes given to the basic_page_pool_t.
        bsl::safe_umx m_size{};
        /// @brief stores the total number of bytes given to the basic_page_pool_t.
        bsl::safe_umx m_used{};
        /// @brief store the virt to phys translations
        bsl::unordered_map<void const *, bsl::safe_u64> m_virt_to_phys{};
        /// @brief stores whether or not allocate fails
        bool m_allocate_fails{};

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
        ///   @brief Creates the huge pool given a mutable_buffer_t to
        ///     the huge pool as well as the virtual address base of the
        ///     huge pool which is used for virt to phys translations.
        ///
        /// <!-- inputs/outputs -->
        ///   @param pool the mutable_buffer_t of the huge pool
        ///
        static constexpr void
        initialize(bsl::span<page_4k_t> const &pool) noexcept
        {
            bsl::discard(pool);
        }

        /// <!-- description -->
        ///   @brief Allocates memory from the huge pool.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param pages the total number of pages to allocate.
        ///   @return Returns bsl::span containing the allocated memory
        ///
        [[nodiscard]] constexpr auto
        allocate(tls_t const &tls, bsl::safe_umx const &pages) noexcept -> bsl::span<page_4k_t>
        {
            page_4k_t *pmut_mut_virt{};
            bsl::safe_u64 mut_phys{};

            bsl::discard(tls);

            auto const bytes{(HYPERVISOR_PAGE_SIZE * pages).checked()};
            m_size += bytes;
            m_used += bytes;

            if (m_allocate_fails) {
                return {};
            }

            /// BUG:
            /// - There is a bug in Clang 10 where any array based allocations
            ///   from a constexpr that get their size at runtime will produce
            ///   a segfault in Clang itself. This bug was fixed in Clang 11,
            ///   but Ubuntu 20.04 comes with Clang 10, and our goal is to
            ///   try our best to continue to be able to use Clang 10. So to
            ///   solve this, we hard code the size to something large enough
            ///   that all unit tests should be able to play within this size.
            ///   A ton of memory is wasted doing this, but this is only for
            ///   unit testing, so that should be fine.
            ///
            constexpr auto max_pages{10_umx};
            bsl::expects(pages <= max_pages);

            // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
            pmut_mut_virt = new page_4k_t[max_pages.get()]();
            mut_phys = m_size.checked();

            m_virt_to_phys.at(pmut_mut_virt) = mut_phys;
            return {pmut_mut_virt, pages};
        }

        /// <!-- description -->
        ///   @brief Tells allocate to fail
        ///
        constexpr void
        set_allocate_fails() noexcept
        {
            m_allocate_fails = true;
        }

        /// <!-- description -->
        ///   @brief Not supported
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param buf the bsl::span containing the memory to deallocate
        ///
        constexpr void
        deallocate(tls_t const &tls, bsl::span<page_4k_t> const &buf) noexcept
        {
            bsl::discard(tls);

            m_used -= buf.size();
            delete[] buf.data();    // NOLINT // GRCOV_EXCLUDE_BR
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
            return m_size.checked();
        }

        /// <!-- description -->
        ///   @brief Returns the number of bytes allocated.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @return Returns the number of bytes allocated.
        ///
        [[nodiscard]] constexpr auto
        allocated(tls_t const &tls) const noexcept -> bsl::safe_umx
        {
            bsl::discard(tls);
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
        remaining(tls_t const &tls) const noexcept -> bsl::safe_umx
        {
            bsl::discard(tls);
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

            bsl::expects(nullptr != virt);
            bsl::expects(m_virt_to_phys.contains(virt));

            return m_virt_to_phys.at(virt);
        }

        /// <!-- description -->
        ///   @brief Dumps the page_pool_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///
        static constexpr void
        dump(tls_t const &tls) noexcept
        {
            bsl::discard(tls);
        }
    };
}

#endif
