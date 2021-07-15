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

#ifndef MOCKS_PAGE_POOL_T_HPP
#define MOCKS_PAGE_POOL_T_HPP

#include <tls_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/is_const.hpp>
#include <bsl/is_same.hpp>
#include <bsl/remove_const.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/span.hpp>
#include <bsl/string_view.hpp>
#include <bsl/unlikely.hpp>
#include <bsl/unordered_map.hpp>

namespace mk
{
    /// @brief page_t prototype
    struct page_t;
    /// @brief ext_tcb_t prototype
    struct ext_tcb_t;
    /// @brief pml4t_t prototype
    struct pml4t_t;
    /// @brief pdpt_t prototype
    struct pdpt_t;
    /// @brief pdt_t prototype
    struct pdt_t;
    /// @brief pt_t prototype
    struct pt_t;

    /// @brief stores the max number of records the page pool can store
    constexpr auto PAGE_POOL_MAX_RECORDS{10_umax};

    /// <!-- description -->
    ///   @brief If you see this function in an error, it means that you are
    ///     attempting to perform a deallocation or virt to phys or phys to
    ///     virt translation with an address that was not allocated using
    ///     the page pool which is not supported.
    ///
    inline void
    address_was_not_allocated_using_the_page_pool() noexcept
    {}

    /// <!-- description -->
    ///   @brief If you see this function in an error, it means that you are
    ///     attempting to perform a deallocation on a nullptr. This is not
    ///     allowed, although at runtime this will be safely handled.
    ///
    inline void
    attempting_to_deallocate_nullptr() noexcept
    {}

    /// <!-- description -->
    ///   @brief If you see this function in an error, it means that you are
    ///     attempting to perform a conversion on a nullptr. This is not
    ///     allowed, although at runtime this will be safely handled.
    ///
    inline void
    attempting_to_convert_a_nullptr() noexcept
    {}

    /// <!-- description -->
    ///   @brief If you see this function in an error, it means that you are
    ///     attempting to perform a conversion on an invalid physical address.
    ///     This is not allowed, although at runtime this will be safely
    ///     handled.
    ///
    inline void
    attempting_to_convert_and_invalid_physical_address() noexcept
    {}

    /// @class mk::page_pool_t
    ///
    /// <!-- description -->
    ///   @brief Implements a mocked version of page_pool_t.
    ///
    class page_pool_t final
    {
        /// @brief stores virtual address to tag conversions
        bsl::unordered_map<void const *, bsl::string_view> m_tags{};
        /// @brief stores allocation counts per tag
        bsl::unordered_map<bsl::string_view, bsl::safe_uintmax> m_allocated{};

        /// @brief stores pending physical address for override allocations
        bsl::unordered_map<bsl::string_view, bsl::safe_uintmax> m_allocate_phys{};
        /// @brief stores virt to phys translations
        bsl::unordered_map<void const *, bsl::safe_uintmax> m_virt_to_phys{};
        /// @brief stores virt to phys translation overrides
        bsl::unordered_map<void const *, bsl::safe_uintmax> m_virt_to_phys_ret{};

        /// @brief stores pending virtual address for override allocations
        bsl::unordered_map<bsl::string_view, page_t *> m_allocate_virt_page_t{};
        /// @brief stores phys to virt translations
        bsl::unordered_map<bsl::safe_uintmax, page_t *> m_phys_to_virt_page_t{};
        /// @brief stores phys to virt translation overrides
        bsl::unordered_map<bsl::safe_uintmax, page_t *> m_phys_to_virt_page_t_ret{};

        /// @brief stores pending virtual address for override allocations
        bsl::unordered_map<bsl::string_view, ext_tcb_t *> m_allocate_virt_ext_tcb_t{};
        /// @brief stores phys to virt translations
        bsl::unordered_map<bsl::safe_uintmax, ext_tcb_t *> m_phys_to_virt_ext_tcb_t{};
        /// @brief stores phys to virt translation overrides
        bsl::unordered_map<bsl::safe_uintmax, ext_tcb_t *> m_phys_to_virt_ext_tcb_t_ret{};

        /// @brief stores pending virtual address for override allocations
        bsl::unordered_map<bsl::string_view, pml4t_t *> m_allocate_virt_pml4t_t{};
        /// @brief stores phys to virt translations
        bsl::unordered_map<bsl::safe_uintmax, pml4t_t *> m_phys_to_virt_pml4t_t{};
        /// @brief stores phys to virt translation overrides
        bsl::unordered_map<bsl::safe_uintmax, pml4t_t *> m_phys_to_virt_pml4t_t_ret{};

        /// @brief stores pending virtual address for override allocations
        bsl::unordered_map<bsl::string_view, pdpt_t *> m_allocate_virt_pdpt_t{};
        /// @brief stores phys to virt translations
        bsl::unordered_map<bsl::safe_uintmax, pdpt_t *> m_phys_to_virt_pdpt_t{};
        /// @brief stores phys to virt translation overrides
        bsl::unordered_map<bsl::safe_uintmax, pdpt_t *> m_phys_to_virt_pdpt_t_ret{};

        /// @brief stores pending virtual address for override allocations
        bsl::unordered_map<bsl::string_view, pdt_t *> m_allocate_virt_pdt_t{};
        /// @brief stores phys to virt translations
        bsl::unordered_map<bsl::safe_uintmax, pdt_t *> m_phys_to_virt_pdt_t{};
        /// @brief stores phys to virt translation overrides
        bsl::unordered_map<bsl::safe_uintmax, pdt_t *> m_phys_to_virt_pdt_t_ret{};

        /// @brief stores pending virtual address for override allocations
        bsl::unordered_map<bsl::string_view, pt_t *> m_allocate_virt_pt_t{};
        /// @brief stores phys to virt translations
        bsl::unordered_map<bsl::safe_uintmax, pt_t *> m_phys_to_virt_pt_t{};
        /// @brief stores phys to virt translation overrides
        bsl::unordered_map<bsl::safe_uintmax, pt_t *> m_phys_to_virt_pt_t_ret{};

    public:
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
        allocate(tls_t const &tls, bsl::string_view const &tag) noexcept -> T *
        {
            static_assert(sizeof(T) == HYPERVISOR_PAGE_SIZE);
            static_assert(!bsl::is_const<T>::value, "allocating a const makes no sense");

            /// NOTE:
            /// - If you see the above static_assert trigger, it is because
            ///   you are trying to allocate a const pointer, which is not
            ///   supported. Most malloc()/free() engines, which is what
            ///   new/delete use return a void *, not a void const *, and
            ///   converting between them is not trivial. In general, there
            ///   isn't much of a reason to be trying to allocate memory
            ///   that you cannot modify.
            ///

            bsl::discard(tls);

            if (bsl::unlikely(tag.empty())) {
                bsl::error() << "invalid tag\n" << bsl::here();
                return nullptr;
            }

            if (bsl::unlikely(PAGE_POOL_MAX_RECORDS == m_allocated.size())) {
                bsl::error() << "page pool out of space for tags\n" << bsl::here();
                return nullptr;
            }

            T *pmut_mut_virt{};
            bsl::safe_uintmax mut_phys{};

            if (m_allocate_phys.contains(tag)) {
                if constexpr (bsl::is_same<T, pml4t_t>::value) {
                    pmut_mut_virt = m_allocate_virt_pml4t_t.at(tag);
                    m_allocate_virt_pml4t_t.at(tag) = {};
                }
                else if constexpr (bsl::is_same<T, pdpt_t>::value) {
                    pmut_mut_virt = m_allocate_virt_pdpt_t.at(tag);
                    m_allocate_virt_pdpt_t.at(tag) = {};
                }
                else if constexpr (bsl::is_same<T, pdt_t>::value) {
                    pmut_mut_virt = m_allocate_virt_pdt_t.at(tag);
                    m_allocate_virt_pdt_t.at(tag) = {};
                }
                else if constexpr (bsl::is_same<T, pt_t>::value) {
                    pmut_mut_virt = m_allocate_virt_pt_t.at(tag);
                    m_allocate_virt_pt_t.at(tag) = {};
                }
                else if constexpr (bsl::is_same<T, ext_tcb_t>::value) {
                    pmut_mut_virt = m_allocate_virt_ext_tcb_t.at(tag);
                    m_allocate_virt_ext_tcb_t.at(tag) = {};
                }
                else {
                    pmut_mut_virt = m_allocate_virt_page_t.at(tag);
                    m_allocate_virt_page_t.at(tag) = {};
                }

                mut_phys = m_allocate_phys.at(tag);
                m_allocate_phys.at(tag) = {};

                if (nullptr == pmut_mut_virt) {
                    bsl::error() << "mock is purposely returning an error\n" << bsl::here();
                    return nullptr;
                }

                m_tags.at(pmut_mut_virt) = tag;
            }
            else {
                // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
                pmut_mut_virt = new T{};
                m_tags.at(pmut_mut_virt) = tag;
                mut_phys = m_tags.size() * HYPERVISOR_PAGE_SIZE;
            }

            m_allocated.at(tag) += HYPERVISOR_PAGE_SIZE;
            m_virt_to_phys.at(pmut_mut_virt) = mut_phys;

            if constexpr (bsl::is_same<T, pml4t_t>::value) {
                m_phys_to_virt_pml4t_t.at(mut_phys) = pmut_mut_virt;
            }
            else if constexpr (bsl::is_same<T, pdpt_t>::value) {
                m_phys_to_virt_pdpt_t.at(mut_phys) = pmut_mut_virt;
            }
            else if constexpr (bsl::is_same<T, pdt_t>::value) {
                m_phys_to_virt_pdt_t.at(mut_phys) = pmut_mut_virt;
            }
            else if constexpr (bsl::is_same<T, pt_t>::value) {
                m_phys_to_virt_pt_t.at(mut_phys) = pmut_mut_virt;
            }
            else if constexpr (bsl::is_same<T, ext_tcb_t>::value) {
                m_phys_to_virt_ext_tcb_t.at(mut_phys) = pmut_mut_virt;
            }
            else {
                m_phys_to_virt_page_t.at(mut_phys) = pmut_mut_virt;
            }

            return pmut_mut_virt;
        }

        /// <!-- description -->
        ///   @brief Sets the return value of allocate() for a specific tag. If
        ///     this function is not used, memory will be allocated using
        ///     the new operator. Once the page has been allocated, this
        ///     allocate() will return nullptr on future allocations.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of pointer to return
        ///   @param tag the tag to mark the allocation with
        ///   @param pudm_virt the virtual address to return when allocate is
        ///     executed.
        ///   @param phys the physical address of the virtual address to
        ///     use when virt_to_phys()/phys_to_virt() are called.
        ///
        template<typename T>
        constexpr void
        set_allocate(
            bsl::string_view const &tag, T *const pudm_virt, bsl::safe_uintmax const &phys) noexcept
        {
            if constexpr (bsl::is_same<T, pml4t_t>::value) {
                m_allocate_virt_pml4t_t.at(tag) = pudm_virt;
            }
            else if constexpr (bsl::is_same<T, pdpt_t>::value) {
                m_allocate_virt_pdpt_t.at(tag) = pudm_virt;
            }
            else if constexpr (bsl::is_same<T, pdt_t>::value) {
                m_allocate_virt_pdt_t.at(tag) = pudm_virt;
            }
            else if constexpr (bsl::is_same<T, pt_t>::value) {
                m_allocate_virt_pt_t.at(tag) = pudm_virt;
            }
            else if constexpr (bsl::is_same<T, ext_tcb_t>::value) {
                m_allocate_virt_ext_tcb_t.at(tag) = pudm_virt;
            }
            else {
                m_allocate_virt_page_t.at(tag) = pudm_virt;
            }

            m_allocate_phys.at(tag) = phys;
        }

        /// <!-- description -->
        ///   @brief Returns a page previously allocated using the allocate
        ///     function to the page pool.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of pointer to deallocate
        ///   @param tls the current TLS block
        ///   @param pmut_virt the pointer to the page to deallocate
        ///   @param tag the tag the allocation was marked with
        ///
        template<typename T>
        constexpr void
        deallocate(tls_t const &tls, T *const pmut_virt, bsl::string_view const &tag) noexcept
        {
            static_assert(sizeof(T) == HYPERVISOR_PAGE_SIZE);
            bsl::discard(tls);

            if (bsl::unlikely(nullptr == pmut_virt)) {
                attempting_to_deallocate_nullptr();
                bsl::error() << "attempting to deallocate nullptr\n" << bsl::here();
                return;
            }

            if (bsl::unlikely(!m_tags.contains(pmut_virt))) {
                address_was_not_allocated_using_the_page_pool();
                bsl::error() << "address was not allocated using the page pool\n" << bsl::here();
                return;
            }

            if (m_allocate_phys.contains(tag)) {
                bsl::discard(m_allocate_virt_page_t.erase(tag));
            }
            else {
                // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
                delete pmut_virt;    // GRCOV_EXCLUDE_BR
            }

            bsl::discard(m_tags.erase(pmut_virt));
            m_allocated.at(tag) -= HYPERVISOR_PAGE_SIZE;

            auto const phys{m_virt_to_phys.at(pmut_virt)};
            bsl::discard(m_virt_to_phys.erase(pmut_virt));

            if constexpr (bsl::is_same<T, pml4t_t>::value) {
                bsl::discard(m_phys_to_virt_pml4t_t.erase(phys));
            }
            else if constexpr (bsl::is_same<T, pdpt_t>::value) {
                bsl::discard(m_phys_to_virt_pdpt_t.erase(phys));
            }
            else if constexpr (bsl::is_same<T, pdt_t>::value) {
                bsl::discard(m_phys_to_virt_pdt_t.erase(phys));
            }
            else if constexpr (bsl::is_same<T, pt_t>::value) {
                bsl::discard(m_phys_to_virt_pt_t.erase(phys));
            }
            else if constexpr (bsl::is_same<T, ext_tcb_t>::value) {
                bsl::discard(m_phys_to_virt_ext_tcb_t.erase(phys));
            }
            else {
                bsl::discard(m_phys_to_virt_page_t.erase(phys));
            }
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
        allocated(tls_t const &tls, bsl::string_view const &tag) noexcept -> bsl::safe_uintmax
        {
            bsl::discard(tls);

            if (bsl::unlikely(!m_allocated.contains(tag))) {
                address_was_not_allocated_using_the_page_pool();
                bsl::error() << "address was not allocated using the page pool\n" << bsl::here();
                return bsl::safe_uintmax::failure();
            }

            return m_allocated.at(tag);
        }

        /// <!-- description -->
        ///   @brief Converts a virtual address to a physical address for
        ///     any page allocated by the page pool. If the provided virt
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
            if (bsl::unlikely(nullptr == virt)) {
                attempting_to_convert_a_nullptr();
                bsl::error() << "attempting to convert a nullptr\n" << bsl::here();
                return bsl::safe_uintmax::failure();
            }

            if (bsl::unlikely(!m_virt_to_phys.contains(virt))) {
                address_was_not_allocated_using_the_page_pool();
                bsl::error() << "address was not allocated using the page pool\n" << bsl::here();
                return bsl::safe_uintmax::failure();
            }

            if (m_virt_to_phys_ret.contains(virt)) {
                auto const ret{m_virt_to_phys_ret.at(virt)};
                if (!ret) {
                    bsl::error() << "mock is purposely returning an error\n" << bsl::here();
                    return ret;
                }

                return ret;
            }

            return m_virt_to_phys.at(virt);
        }

        /// <!-- description -->
        ///   @brief Used to manually define virt to phys translations.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T defines the type of virtual address being converted
        ///   @param pmut_virt the virtual address to convert
        ///   @param phys the physical address to return
        ///
        template<typename T>
        constexpr void
        set_virt_to_phys(T *const pmut_virt, bsl::safe_uintmax const &phys) noexcept
        {
            m_virt_to_phys_ret.at(pmut_virt) = phys;
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
            if (bsl::unlikely(!phys)) {
                attempting_to_convert_and_invalid_physical_address();
                bsl::error() << "attempting to convert an invalid address\n" << bsl::here();
                return nullptr;
            }

            if (bsl::unlikely(phys.is_zero())) {
                attempting_to_convert_a_nullptr();
                bsl::error() << "attempting to convert a nullptr\n" << bsl::here();
                return nullptr;
            }

            if constexpr (bsl::is_same<bsl::remove_const_t<T>, pml4t_t>::value) {
                if (bsl::unlikely(!m_phys_to_virt_pml4t_t.contains(phys))) {
                    address_was_not_allocated_using_the_page_pool();
                    bsl::error() << "address was not allocated using the page pool\n"
                                 << bsl::here();
                    return nullptr;
                }

                if (m_phys_to_virt_pml4t_t_ret.contains(phys)) {
                    auto *const pmut_virt{m_phys_to_virt_pml4t_t_ret.at(phys)};
                    if (nullptr == pmut_virt) {
                        bsl::error() << "mock is purposely returning an error\n" << bsl::here();
                        return pmut_virt;
                    }

                    return pmut_virt;
                }

                return m_phys_to_virt_pml4t_t.at(phys);
            }
            else if constexpr (bsl::is_same<bsl::remove_const_t<T>, pdpt_t>::value) {
                if (bsl::unlikely(!m_phys_to_virt_pdpt_t.contains(phys))) {
                    address_was_not_allocated_using_the_page_pool();
                    bsl::error() << "address was not allocated using the page pool\n"
                                 << bsl::here();
                    return nullptr;
                }

                if (m_phys_to_virt_pdpt_t_ret.contains(phys)) {
                    auto *const pmut_virt{m_phys_to_virt_pdpt_t_ret.at(phys)};
                    if (nullptr == pmut_virt) {
                        bsl::error() << "mock is purposely returning an error\n" << bsl::here();
                        return pmut_virt;
                    }

                    return pmut_virt;
                }

                return m_phys_to_virt_pdpt_t.at(phys);
            }
            else if constexpr (bsl::is_same<bsl::remove_const_t<T>, pdt_t>::value) {
                if (bsl::unlikely(!m_phys_to_virt_pdt_t.contains(phys))) {
                    address_was_not_allocated_using_the_page_pool();
                    bsl::error() << "address was not allocated using the page pool\n"
                                 << bsl::here();
                    return nullptr;
                }

                if (m_phys_to_virt_pdt_t_ret.contains(phys)) {
                    auto *const pmut_virt{m_phys_to_virt_pdt_t_ret.at(phys)};
                    if (nullptr == pmut_virt) {
                        bsl::error() << "mock is purposely returning an error\n" << bsl::here();
                        return pmut_virt;
                    }

                    return pmut_virt;
                }

                return m_phys_to_virt_pdt_t.at(phys);
            }
            else if constexpr (bsl::is_same<bsl::remove_const_t<T>, pt_t>::value) {
                if (bsl::unlikely(!m_phys_to_virt_pt_t.contains(phys))) {
                    address_was_not_allocated_using_the_page_pool();
                    bsl::error() << "address was not allocated using the page pool\n"
                                 << bsl::here();
                    return nullptr;
                }

                if (m_phys_to_virt_pt_t_ret.contains(phys)) {
                    auto *const pmut_virt{m_phys_to_virt_pt_t_ret.at(phys)};
                    if (nullptr == pmut_virt) {
                        bsl::error() << "mock is purposely returning an error\n" << bsl::here();
                        return pmut_virt;
                    }

                    return pmut_virt;
                }

                return m_phys_to_virt_pt_t.at(phys);
            }
            else if constexpr (bsl::is_same<bsl::remove_const_t<T>, ext_tcb_t>::value) {
                if (bsl::unlikely(!m_phys_to_virt_ext_tcb_t.contains(phys))) {
                    address_was_not_allocated_using_the_page_pool();
                    bsl::error() << "address was not allocated using the page pool\n"
                                 << bsl::here();
                    return nullptr;
                }

                if (m_phys_to_virt_ext_tcb_t_ret.contains(phys)) {
                    auto *const pmut_virt{m_phys_to_virt_ext_tcb_t_ret.at(phys)};
                    if (nullptr == pmut_virt) {
                        bsl::error() << "mock is purposely returning an error\n" << bsl::here();
                        return pmut_virt;
                    }

                    return pmut_virt;
                }

                return m_phys_to_virt_ext_tcb_t.at(phys);
            }
            else {
                if (bsl::unlikely(!m_phys_to_virt_page_t.contains(phys))) {
                    address_was_not_allocated_using_the_page_pool();
                    bsl::error() << "address was not allocated using the page pool\n"
                                 << bsl::here();
                    return nullptr;
                }

                if (m_phys_to_virt_page_t_ret.contains(phys)) {
                    auto *const pmut_virt{m_phys_to_virt_page_t_ret.at(phys)};
                    if (nullptr == pmut_virt) {
                        bsl::error() << "mock is purposely returning an error\n" << bsl::here();
                        return pmut_virt;
                    }

                    return pmut_virt;
                }

                return m_phys_to_virt_page_t.at(phys);
            }

            return nullptr;
        }

        /// <!-- description -->
        ///   @brief Used to manually define virt to phys translations.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T defines the type of virtual address to convert to
        ///   @param phys the physical address to convert
        ///   @param pmut_virt the virtual address to return
        ///
        template<typename T>
        constexpr void
        set_phys_to_virt(bsl::safe_uintmax const &phys, T *const pmut_virt) noexcept
        {
            if constexpr (bsl::is_same<T, pml4t_t>::value) {
                m_phys_to_virt_pml4t_t_ret.at(phys) = pmut_virt;
            }
            else if constexpr (bsl::is_same<T, pdpt_t>::value) {
                m_phys_to_virt_pdpt_t_ret.at(phys) = pmut_virt;
            }
            else if constexpr (bsl::is_same<T, pdt_t>::value) {
                m_phys_to_virt_pdt_t_ret.at(phys) = pmut_virt;
            }
            else if constexpr (bsl::is_same<T, pt_t>::value) {
                m_phys_to_virt_pt_t_ret.at(phys) = pmut_virt;
            }
            else if constexpr (bsl::is_same<T, ext_tcb_t>::value) {
                m_phys_to_virt_ext_tcb_t_ret.at(phys) = pmut_virt;
            }
            else {
                m_phys_to_virt_page_t_ret.at(phys) = pmut_virt;
            }
        }

        /// <!-- description -->
        ///   @brief Dumps the page_pool_t
        ///
        constexpr void
        dump() const noexcept
        {}
    };
}

#endif
