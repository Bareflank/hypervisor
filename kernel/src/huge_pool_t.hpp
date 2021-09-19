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

#ifndef HUGE_POOL_T_HPP
#define HUGE_POOL_T_HPP

#include <lock_guard_t.hpp>
#include <page_4k_t.hpp>
#include <spinlock_t.hpp>
#include <tls_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/span.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// @class mk::huge_pool_t
    ///
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
        /// @brief stores the range of memory used by this allocator
        bsl::span<page_4k_t> m_pool{};
        /// @brief stores the huge pool's cursor
        bsl::safe_umx m_crsr{};
        /// @brief safe guards operations on the pool.
        mutable spinlock_t m_lock{};

        /// <!-- description -->
        ///   @brief Converts a virtual address to a physical address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param virt the virtual address to convert
        ///   @return the resulting physical address
        ///
        [[nodiscard]] static constexpr auto
        virt_to_phys(bsl::safe_umx const &virt) noexcept -> bsl::safe_umx
        {
            constexpr auto min_addr{HYPERVISOR_MK_DIRECT_MAP_ADDR};
            constexpr auto max_addr{(min_addr + HYPERVISOR_MK_DIRECT_MAP_SIZE).checked()};

            bsl::expects(virt > min_addr);
            bsl::expects(virt < max_addr);

            auto const phys{(virt - min_addr).checked()};

            bsl::ensures(phys.is_valid_and_checked());
            return phys;
        }

        /// <!-- description -->
        ///   @brief Converts a physical address to a virtual address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param phys the physical address to convert
        ///   @return the resulting virtual address
        ///
        [[nodiscard]] static constexpr auto
        phys_to_virt(bsl::safe_umx const &phys) noexcept -> bsl::safe_umx
        {
            bsl::expects(phys < HYPERVISOR_MK_DIRECT_MAP_SIZE);
            auto const virt{(phys + HYPERVISOR_MK_DIRECT_MAP_ADDR).checked()};

            bsl::ensures(virt.is_valid_and_checked());
            return virt;
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

            return (m_crsr * HYPERVISOR_PAGE_SIZE).checked();
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
        ///   @param mut_pool the mutable_buffer_t of the huge pool
        ///
        constexpr void
        initialize(bsl::span<page_4k_t> &mut_pool) noexcept
        {
            bsl::expects(mut_pool.is_valid());
            m_pool = mut_pool;
        }

        /// <!-- description -->
        ///   @brief Allocates memory from the huge pool.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param pages the total number of pages to allocate.
        ///   @return Returns bsl::span containing the allocated memory
        ///
        [[nodiscard]] constexpr auto
        allocate(tls_t &mut_tls, bsl::safe_umx const &pages) noexcept -> bsl::span<page_4k_t>
        {
            lock_guard_t mut_lock{mut_tls, m_lock};

            bsl::expects(pages.is_valid_and_checked());
            bsl::expects(pages.is_pos());

            auto mut_buf{m_pool.subspan(bsl::to_idx(m_crsr), pages)};
            if (bsl::unlikely(mut_buf.size() != pages)) {
                bsl::error() << "huge pool out of memory\n" << bsl::here();
                return {};
            }

            /// NOTE:
            /// - It is impossible for the following to overflow because if
            ///   it did, the span above would fail first, which is why it
            ///   is marked as checked.
            ///

            m_crsr = (m_crsr + pages).checked();
            bsl::builtin_memset(mut_buf.data(), '\0', mut_buf.size_bytes());

            bsl::ensures(m_crsr.is_valid_and_checked());
            return mut_buf;
        }

        /// <!-- description -->
        ///   @brief Not supported
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param buf the bsl::span containing the memory to deallocate
        ///
        constexpr void
        deallocate(tls_t &mut_tls, bsl::span<page_4k_t> const &buf) noexcept
        {
            lock_guard_t mut_lock{mut_tls, m_lock};
            bsl::discard(buf);

            /// NOTE:
            /// - If this function is implemented, we will have to deal with
            ///   deallocations being a page in size. Specifically, right now
            ///   a huge page is allocated and mapped into the page tables
            ///   one page at a time. When is is time to deallocate, this
            ///   memory is released one page at a time. If the page tables
            ///   are deallocating one page of a larger physically contiguous
            ///   memory region, it should be assumed that the entire region
            ///   will be freed, it will just happen in page increments.
            /// - What this means is this function could see a free for the
            ///   same physically contiguous block of memory (one for each
            ///   page in the block). We could ignore the extras, or we
            ///   could set up the allocator so that it frees one page at a
            ///   time. Just depends on how we want to do this... but in
            ///   general, I would suggest using the later as a buddy allocator
            ///   can support this without any added overhead.
            ///
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
            /// NOTE:
            /// - The following is marked checked because the initialize
            ///   function ensures this math will never overflow.
            ///

            return (m_pool.size() * HYPERVISOR_PAGE_SIZE).checked();
        }

        /// <!-- description -->
        ///   @brief Returns the number of bytes allocated.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @return Returns the number of bytes allocated.
        ///
        [[nodiscard]] constexpr auto
        allocated(tls_t &mut_tls) const noexcept -> bsl::safe_umx
        {
            lock_guard_t mut_lock{mut_tls, m_lock};
            return this->allocated();
        }

        /// <!-- description -->
        ///   @brief Returns this->size() - this->allocated().
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @return Returns this->size() - this->allocated().
        ///
        [[nodiscard]] constexpr auto
        remaining(tls_t &mut_tls) const noexcept -> bsl::safe_umx
        {
            lock_guard_t mut_lock{mut_tls, m_lock};
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
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            return reinterpret_cast<T *>(this->phys_to_virt(phys).get());
        }

        /// <!-- description -->
        ///   @brief Dumps the page_pool_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///
        constexpr void
        dump(tls_t &mut_tls) const noexcept
        {
            lock_guard_t mut_lock{mut_tls, m_lock};

            constexpr auto kb{1024_umx};
            constexpr auto mb{kb * kb};

            bsl::print() << bsl::mag << "huge pool dump: ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Header
            ///

            bsl::print() << bsl::ylw << "+-----------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::cyn << bsl::fmt{"^12s", "description "};
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::cyn << bsl::fmt{"^8s", "value "};
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            bsl::print() << bsl::ylw << "+-----------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            /// Total
            ///

            auto const total_kb{(this->size() / kb).checked()};
            auto const total_mb{(this->size() / mb).checked()};

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<12s", "total "};
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
            bsl::print() << bsl::rst << bsl::fmt{"<12s", "used "};
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
            bsl::print() << bsl::rst << bsl::fmt{"<12s", "remaining "};
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

            bsl::print() << bsl::ylw << "+-----------------------+";
            bsl::print() << bsl::rst << bsl::endl;
        }
    };
}

#endif
