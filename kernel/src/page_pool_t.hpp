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

#include <bsl/construct_at.hpp>
#include <bsl/convert.hpp>
#include <bsl/cstring.hpp>
#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/finally.hpp>
#include <bsl/is_pointer.hpp>
#include <bsl/is_standard_layout.hpp>
#include <bsl/is_void.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// @class mk::page_pool_t
    ///
    /// <!-- description -->
    ///   @brief The page pool is responsible for allocating and freeing
    ///      pages. The page pool exists in the MK's direct map and so the
    ///      page pool can also return the physical address of any page
    ///      that it has allocated. The page pool itself is actually initalized
    ///      by the loader, which has all of the information about each page
    ///      in the pool as well as what it's physical address is, which is
    ///      encoded in the resulting virtual address, thus creating a
    ///      direct map. The way that the loader sets this page pool up is
    ///      as follows:
    ///
    ///      ----------       ----------       ----------
    ///      | [] ----|------>| [] ----|------>|        |
    ///      |        |       |        |       |        |
    ///      |        |       |        |       |        |
    ///      ----------       ----------       ----------
    ///
    ///      The head (a void *) is actually a pointer to another void *. Each
    ///      pointer actually points to a page, and it assumes that the first
    ///      64bits in the page are a pointer to the next page. This is
    ///      repeated until the last page is linked which stores a nullptr.
    ///      To allocate, all you have to do is pop off of the head of the
    ///      stack and set the new head to the page the popped page was
    ///      storing. To deallocate, all you have to do is set the page being
    ///      deallocated to point to the current head, and then set the head
    ///      to this newly deallocated page. This ensures the page pool can
    ///      allocate and deallocate in O(1), and there is no metadata that
    ///      is needed, so no additional overhead.
    ///
    ///      To handle virt to phys and phys to virt conversions, each page
    ///      is mapped into the microkernel's address space at the physical
    ///      address + some offset. This means that virt to phys conversions
    ///      can all be done with simple arithmetic (i.e., no lookups are
    ///      needed). This is what is typically called a direct map. In other
    ///      kernels, the direct map has been an issue with respect to attacks
    ///      like Spectre/Meltdown. In the case of this microkernel, the only
    ///      memory in the direct map is memory used by the page/huge pools,
    ///      all of which do not store secrects or VM memory, but instead
    ///      are used by the microkernel for internal resources, hardware
    ///      resources and memory to back extensions, all of which should not
    ///      have secrects in them. On the flip side, kernels typically have
    ///      more conventional userspace processes and their associated memory
    ///      as well as kernel memory all mapped into the direct map, which
    ///      could include secrets like encryption keys, passwords, etc. If
    ///      secrets are needed, they should be stored in global or stack based
    ///      memory in the microkernel (not in an extension), and the
    ///      microkernel should be the only thing working with the unprotected
    ///      version of the secret.
    ///
    /// <!-- template parameters -->
    ///   @tparam PAGE_SIZE defines the size of a page
    ///
    template<bsl::uintmax PAGE_SIZE>
    class page_pool_t final
    {
        /// @brief stores true if initialized() has been executed
        bool m_initialized{};
        /// @brief stores the head of the page pool stack.
        void *m_head{};
        /// @brief stores the total number of bytes in the page pool.
        bsl::safe_uintmax m_size{bsl::safe_uintmax::zero(true)};
        /// @brief stores the virtual address base of the page pool.
        bsl::safe_uintmax m_base_virt{bsl::safe_uintmax::zero(true)};

    public:
        /// <!-- description -->
        ///   @brief Default constructor
        ///
        constexpr page_pool_t() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates the page pool given a mutable_buffer_t to
        ///     the page pool as well as the virtual address base of the
        ///     page pool which is used for virt to phys translations.
        ///
        /// <!-- inputs/outputs -->
        ///   @param pool the mutable_buffer_t of the page pool
        ///   @param base_virt the base virtual address base of the page pool
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(bsl::span<bsl::byte> &pool, bsl::safe_uintmax const &base_virt) &noexcept
            -> bsl::errc_type
        {
            if (bsl::unlikely(m_initialized)) {
                bsl::error() << "page_pool_t already initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            bsl::finally release_on_error{[this]() noexcept -> void {
                this->release();
            }};

            if (bsl::unlikely(pool.empty())) {
                m_head = nullptr;
                m_size = bsl::safe_uintmax::zero(true);
                m_base_virt = bsl::safe_uintmax::zero(true);

                bsl::error() << "pool is empty\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(base_virt.is_zero())) {
                m_head = nullptr;
                m_size = bsl::safe_uintmax::zero(true);
                m_base_virt = bsl::safe_uintmax::zero(true);

                bsl::error() << "base_virt is 0 or invalid\n" << bsl::here();
                return bsl::errc_failure;
            }

            m_head = pool.data();
            m_size = pool.size();
            m_base_virt = base_virt;

            release_on_error.ignore();
            m_initialized = true;

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Release the page_pool_t
        ///
        constexpr void
        release() &noexcept
        {
            m_base_virt = bsl::safe_uintmax::zero(true);
            m_size = bsl::safe_uintmax::zero(true);
            m_head = {};

            m_initialized = {};
        }

        /// <!-- description -->
        ///   @brief Destroyes a previously created page_pool_t
        ///
        constexpr ~page_pool_t() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr page_pool_t(page_pool_t const &o) noexcept = delete;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr page_pool_t(page_pool_t &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(page_pool_t const &o) &noexcept
            -> page_pool_t & = delete;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(page_pool_t &&o) &noexcept
            -> page_pool_t & = default;

        /// <!-- description -->
        ///   @brief Allocates a page from the page pool.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of pointer to return
        ///   @return Returns a pointer to the newly allocated page
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        allocate() &noexcept -> T *
        {
            if (bsl::unlikely(!m_initialized)) {
                bsl::error() << "page_pool_t not initialized\n" << bsl::here();
                return nullptr;
            }

            if (bsl::unlikely(nullptr == m_head)) {
                bsl::error() << "page pool out of pages\n" << bsl::here();
                return nullptr;
            }

            void *const ptr{m_head};
            m_head = *static_cast<void **>(m_head);

            bsl::builtin_memset(ptr, '\0', PAGE_SIZE);

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
        deallocate(void *const ptr) &noexcept
        {
            if (bsl::unlikely(!m_initialized)) {
                bsl::error() << "page_pool_t not initialized\n" << bsl::here();
                return;
            }

            if (bsl::unlikely(nullptr == ptr)) {
                return;
            }

            /// TODO:
            /// - If the address is not in the right range (i.e., not the
            ///   direct map), this function should return and throw up an
            ///   error and return
            ///

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
        virt_to_phys(T const virt) const &noexcept -> bsl::safe_uintmax
        {
            static_assert(bsl::is_pointer<T>::value);
            static_assert(bsl::is_standard_layout<T>::value);

            if (bsl::unlikely(!m_initialized)) {
                bsl::error() << "page_pool_t not initialized\n" << bsl::here();
                return bsl::safe_uintmax::zero(true);
            }

            auto const ret{bsl::to_umax(virt) - m_base_virt};
            if (bsl::unlikely(!ret)) {
                bsl::error() << "virtual to physical address conversion failed for "    // --
                             << virt                                                    // --
                             << bsl::endl                                               // --
                             << bsl::here();                                            // --

                return bsl::safe_uintmax::zero(true);
            }

            return ret;
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
        phys_to_virt(bsl::safe_uintmax const &phys) const &noexcept -> T
        {
            static_assert(bsl::is_pointer<T>::value);
            static_assert(bsl::is_standard_layout<T>::value);

            if (bsl::unlikely(!m_initialized)) {
                bsl::error() << "page_pool_t not initialized\n" << bsl::here();
                return nullptr;
            }

            auto const ret{phys + m_base_virt};
            if (bsl::unlikely(!ret)) {
                bsl::error() << "physical to virtual address conversion failed for "    // --
                             << bsl::hex(phys)                                          // --
                             << bsl::endl                                               // --
                             << bsl::here();                                            // --

                return nullptr;
            }

            return bsl::to_ptr<T>(ret);
        }
    };
}

#endif
