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

#include "lock_guard.hpp"
#include "spinlock.hpp"

#include <bsl/construct_at.hpp>
#include <bsl/convert.hpp>
#include <bsl/cstring.hpp>
#include <bsl/debug.hpp>
#include <bsl/disjunction.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/finally.hpp>
#include <bsl/is_standard_layout.hpp>
#include <bsl/is_void.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/span.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace example
{
    /// @class example::page_pool_t
    ///
    /// <!-- description -->
    ///   @brief The page pool is responsible for allocating and freeing
    ///      pages. The page pool exists in the extensions's direct map and so
    ///      the page pool can also return the physical address of any page
    ///      that it has allocated. For more information about how this page
    ///      pool works, see the page_pool_t in the kernel, as they are
    ///      very similar.
    ///
    ///      One question you might ask if, why have a page_pool_t in the
    ///      extension in the first place? The reason is because some
    ///      microkernel implementation might not implement the free_page
    ///      ABI as it is optional, but the extension will still need to be
    ///      able to free memory and reuse it. For this reason, all allocations
    ///      are done using this class, instead of allocating memory manually.
    ///      Any time memory is freed, it is returned to the page pool to be
    ///      used again on the next allocation, and any time an allocation
    ///      occurs and there isn't enough memory, the extension asks the
    ///      kernel for another page. This way, the extension is only asking
    ///      for pages when it needs it, and it is able to reuse memory
    ///      when it is freed.
    ///
    class page_pool_t final
    {
        /// @brief stores the handle used to communicate with the kernel
        syscall::bf_handle_t m_handle{};
        /// @brief stores the head of the page pool stack.
        void *m_head{};
        /// @brief stores the total number of bytes in the page pool.
        bsl::safe_umx m_size{};
        /// @brief safe guards operations on the pool.
        mutable spinlock m_pool_lock{};

    public:
        /// <!-- description -->
        ///   @brief Initializes the page pool
        ///
        /// <!-- inputs/outputs -->
        ///   @param handle the handle used to communicate with the kernel
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(syscall::bf_handle_t const &handle) noexcept -> bsl::errc_type
        {
            bsl::finally release_on_error{[this]() noexcept -> void {
                this->release();
            }};

            m_handle = handle;

            release_on_error.ignore();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Release the page_pool_t
        ///
        constexpr void
        release() noexcept
        {
            m_size = {};
            m_head = {};

            m_handle = {};
        }

        /// <!-- description -->
        ///   @brief Allocates a page from the page pool.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of pointer to return
        ///   @return Returns a pointer to the newly allocated page
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        allocate() noexcept -> T *
        {
            lock_guard lock{m_pool_lock};

            if (bsl::unlikely(nullptr == m_head)) {
                m_head = syscall::bf_mem_op_alloc_page(m_handle);
                if (bsl::unlikely(nullptr == m_head)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return nullptr;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            void *const ptr{m_head};
            m_head = *static_cast<void **>(m_head);

            bsl::builtin_memset(ptr, '\0', bsl::to_umx(HYPERVISOR_PAGE_SIZE).get());

            if constexpr (!bsl::is_void<T>::value) {
                static_assert(bsl::is_standard_layout<T>::value, "T must be a standard layout");
                bsl::construct_at<T>(ptr);
            }

            return static_cast<T *>(ptr);
        }

        /// <!-- description -->
        ///   @brief Returns a page previously allocated using the allocate
        ///     function to the page pool.
        ///
        /// <!-- inputs/outputs -->
        ///   @param ptr the pointer to the page to deallocate
        ///
        constexpr void
        deallocate(void *const ptr) noexcept
        {
            lock_guard lock{m_pool_lock};

            if (bsl::unlikely(nullptr == ptr)) {
                return;
            }

            if (bsl::to_umx(ptr) < bsl::to_umx(HYPERVISOR_EXT_PAGE_POOL_ADDR)) {
                bsl::error() << "invalid ptr"    // --
                             << ptr              // --
                             << bsl::endl        // --
                             << bsl::here();

                return;
            }

            *static_cast<void **>(ptr) = m_head;
            m_head = ptr;
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
        virt_to_phys(T const *const virt) const noexcept -> bsl::safe_umx
        {
            static_assert(bsl::disjunction<bsl::is_void<T>, bsl::is_standard_layout<T>>::value);
            return bsl::to_umx(virt) - bsl::to_umx(HYPERVISOR_EXT_PAGE_POOL_ADDR);
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
        phys_to_virt(bsl::safe_umx const &phys) const noexcept -> T *
        {
            static_assert(bsl::disjunction<bsl::is_void<T>, bsl::is_standard_layout<T>>::value);
            return bsl::to_ptr<T *>(phys + bsl::to_umx(HYPERVISOR_EXT_PAGE_POOL_ADDR));
        }
    };
}

#endif
