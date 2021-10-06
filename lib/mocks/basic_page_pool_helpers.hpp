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

#ifndef MOCK_BASIC_PAGE_POOL_HELPERS_HPP
#define MOCK_BASIC_PAGE_POOL_HELPERS_HPP

#include <basic_page_4k_t.hpp>
#include <basic_page_pool_node_t.hpp>
#include <basic_page_table_t.hpp>
#include <ext_tcb_t.hpp>
#include <l0e_t.hpp>
#include <l1e_t.hpp>
#include <l2e_t.hpp>
#include <l3e_t.hpp>
#include <vmcb_t.hpp>
#include <vmcs_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/expects.hpp>
#include <bsl/is_same.hpp>
#include <bsl/remove_cvref.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/typename.hpp>

namespace helpers
{
    /// @brief defines l3t_t
    using l3t_t = lib::basic_page_table_t<lib::l3e_t>;
    /// @brief defines l2t_t
    using l2t_t = lib::basic_page_table_t<lib::l2e_t>;
    /// @brief defines l1t_t
    using l1t_t = lib::basic_page_table_t<lib::l1e_t>;
    /// @brief defines l0t_t
    using l0t_t = lib::basic_page_table_t<lib::l0e_t>;

    /// <!-- description -->
    ///   @brief Defines storage for all of the phys to virt translations.
    ///     We cannot store a void * in the phys to virt map as this is not
    ///     supported in a constexpr. But we can use a union so long as the
    ///     active member of the union is handled properly. So instead of
    ///     storing a void *, we store a union with all of the types that
    ///     we need in a unit test, and then provide set/get functions for
    ///     the mock page pool so that it can set/get the pointer from this
    ///     union, preventing the need to cast a void *.
    ///
    // NOLINTNEXTLINE(bsl-user-defined-type-names-match-header-name)
    struct page_pool_storage_t final
    {
        /// @brief store a l3t_t pointer
        l3t_t *l3t_virt;
        /// @brief stores is the physical address of l3t_virt
        bsl::safe_u64 l3t_phys;
        /// @brief store a l2t_t pointer
        l2t_t *l2t_virt;
        /// @brief stores is the physical address of l2t_virt
        bsl::safe_u64 l2t_phys;
        /// @brief store a l1t_t pointer
        l1t_t *l1t_virt;
        /// @brief stores is the physical address of l1t_virt
        bsl::safe_u64 l1t_phys;
        /// @brief store a l0t_t pointer
        l0t_t *l0t_virt;
        /// @brief stores is the physical address of l0t_virt
        bsl::safe_u64 l0t_phys;
        /// @brief store a basic_page_4k_t pointer
        lib::basic_page_4k_t *basic_page_4k_virt;
        /// @brief stores is the physical address of basic_page_4k_virt
        bsl::safe_u64 basic_page_4k_phys;
        /// @brief store a basic_page_pool_node_t pointer
        lib::basic_page_pool_node_t *basic_page_pool_node_virt;
        /// @brief stores is the physical address of basic_page_pool_node_virt
        bsl::safe_u64 basic_page_pool_node_phys;
        /// @brief store a ext_tcb_t pointer
        mk::ext_tcb_t *ext_tcb_virt;
        /// @brief stores is the physical address of ext_tcb_t
        bsl::safe_u64 ext_tcb_phys;
        /// @brief store a vmcb_t pointer
        mk::vmcb_t *vmcb_virt;
        /// @brief stores is the physical address of vmcb_t
        bsl::safe_u64 vmcb_phys;
        /// @brief store a vmcs_t pointer
        mk::vmcs_t *vmcs_virt;
        /// @brief stores is the physical address of vmcs_t
        bsl::safe_u64 vmcs_phys;
    };

    /// <!-- description -->
    ///   @brief Sets the phys to virt translation in the provided map based
    ///     on the provided type T.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of virtual address to store
    ///   @param mut_store the page_pool_storage_t to store the pointer in
    ///   @param pmut_virt the virtual address of the pointer to set
    ///   @param phys phys the physical address of the pointer to set
    ///
    template<typename T>
    constexpr void
    set_page_pool_storage(
        page_pool_storage_t &mut_store, T *const pmut_virt, bsl::safe_u64 const &phys) noexcept
    {
        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, l3t_t>::value) {
            mut_store.l3t_virt = pmut_virt;
            mut_store.l3t_phys = phys;
            return;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, l2t_t>::value) {
            mut_store.l2t_virt = pmut_virt;
            mut_store.l2t_phys = phys;
            return;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, l1t_t>::value) {
            mut_store.l1t_virt = pmut_virt;
            mut_store.l1t_phys = phys;
            return;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, l0t_t>::value) {
            mut_store.l0t_virt = pmut_virt;
            mut_store.l0t_phys = phys;
            return;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, lib::basic_page_4k_t>::value) {
            mut_store.basic_page_4k_virt = pmut_virt;
            mut_store.basic_page_4k_phys = phys;
            return;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, lib::basic_page_pool_node_t>::value) {
            mut_store.basic_page_pool_node_virt = pmut_virt;
            mut_store.basic_page_pool_node_phys = phys;
            return;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, mk::ext_tcb_t>::value) {
            mut_store.ext_tcb_virt = pmut_virt;
            mut_store.ext_tcb_phys = phys;
            return;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, mk::vmcb_t>::value) {
            mut_store.vmcb_virt = pmut_virt;
            mut_store.vmcb_phys = phys;
            return;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, mk::vmcs_t>::value) {
            mut_store.vmcs_virt = pmut_virt;
            mut_store.vmcs_phys = phys;
            return;
        }

        bsl::error() << "not implemented: " << bsl::type_name<T>() << bsl::endl;    // GRCOV_EXCLUDE
        bsl::expects(false);                                                        // GRCOV_EXCLUDE
    }

    /// <!-- description -->
    ///   @brief Deallocate and clear the storage
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam PAGE_POOL_TYPE the type of page_pool_t to use
    ///   @param mut_page_pool the page_pool_t to use
    ///   @param store the store to deallocate and clear
    ///
    template<typename PAGE_POOL_TYPE>
    constexpr void
    clr_page_pool_storage(PAGE_POOL_TYPE &mut_page_pool, page_pool_storage_t const &store) noexcept
    {
        if (nullptr != store.l3t_virt) {
            mut_page_pool.deallocate({}, store.l3t_virt);
            return;
        }

        if (nullptr != store.l2t_virt) {
            mut_page_pool.deallocate({}, store.l2t_virt);
            return;
        }

        if (nullptr != store.l1t_virt) {
            mut_page_pool.deallocate({}, store.l1t_virt);
            return;
        }

        if (nullptr != store.l0t_virt) {
            mut_page_pool.deallocate({}, store.l0t_virt);
            return;
        }

        if (nullptr != store.basic_page_4k_virt) {
            mut_page_pool.deallocate({}, store.basic_page_4k_virt);
            return;
        }

        if (nullptr != store.basic_page_pool_node_virt) {
            mut_page_pool.deallocate({}, store.basic_page_pool_node_virt);
            return;
        }

        if (nullptr != store.ext_tcb_virt) {
            mut_page_pool.deallocate({}, store.ext_tcb_virt);
            return;
        }

        if (nullptr != store.vmcb_virt) {
            mut_page_pool.deallocate({}, store.vmcb_virt);
            return;
        }

        if (nullptr != store.vmcs_virt) {    // GRCOV_EXCLUDE_BR
            mut_page_pool.deallocate({}, store.vmcs_virt);
            return;
        }

        bsl::expects(false);    // GRCOV_EXCLUDE
    }

    /// <!-- description -->
    ///   @brief Returns true if the page_pool_storage_t is of type T. Returns
    ///     false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T type type to query
    ///   @param store the page_pool_storage_t to query
    ///   @return Returns true if the page_pool_storage_t is of type T. Returns
    ///     false otherwise.
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    is_page_pool_storage_set(page_pool_storage_t const &store) noexcept -> bool
    {
        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, l3t_t>::value) {
            return store.l3t_phys.is_pos();
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, l2t_t>::value) {
            return store.l2t_phys.is_pos();
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, l1t_t>::value) {
            return store.l1t_phys.is_pos();
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, l0t_t>::value) {
            return store.l0t_phys.is_pos();
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, lib::basic_page_4k_t>::value) {
            return store.basic_page_4k_phys.is_pos();
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, lib::basic_page_pool_node_t>::value) {
            return store.basic_page_pool_node_phys.is_pos();
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, mk::ext_tcb_t>::value) {
            return store.ext_tcb_phys.is_pos();
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, mk::vmcb_t>::value) {
            return store.vmcb_phys.is_pos();
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, mk::vmcs_t>::value) {
            return store.vmcs_phys.is_pos();
        }

        bsl::error() << "not implemented: " << bsl::type_name<T>() << bsl::endl;    // GRCOV_EXCLUDE
        bsl::expects(false);                                                        // GRCOV_EXCLUDE
        return {};                                                                  // GRCOV_EXCLUDE
    }

    /// <!-- description -->
    ///   @brief Returns a previously stored virt based on the provided
    ///     type T. Note that the type T must match the type T previously set.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of virtual address to get
    ///   @param store where to get the virtual address from
    ///   @return Returns a previously stored virt based on the provided
    ///     type T. Note that the type T must match the type T previously set.
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    get_virt(page_pool_storage_t const &store) noexcept -> T *
    {
        bsl::expects(is_page_pool_storage_set<T>(store));

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, l3t_t>::value) {
            return store.l3t_virt;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, l2t_t>::value) {
            return store.l2t_virt;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, l1t_t>::value) {
            return store.l1t_virt;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, l0t_t>::value) {
            return store.l0t_virt;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, lib::basic_page_4k_t>::value) {
            return store.basic_page_4k_virt;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, lib::basic_page_pool_node_t>::value) {
            return store.basic_page_pool_node_virt;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, mk::ext_tcb_t>::value) {
            return store.ext_tcb_virt;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, mk::vmcb_t>::value) {
            return store.vmcb_virt;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, mk::vmcs_t>::value) {
            return store.vmcs_virt;
        }

        bsl::error() << "not implemented: " << bsl::type_name<T>() << bsl::endl;    // GRCOV_EXCLUDE
        bsl::expects(false);                                                        // GRCOV_EXCLUDE
        return {};                                                                  // GRCOV_EXCLUDE
    }

    /// <!-- description -->
    ///   @brief Returns a previously stored phys based on the provided
    ///     type T. Note that the type T must match the type T previously set.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of virtual address to get
    ///   @param store where to get the physical address from
    ///   @return Returns a previously stored phys based on the provided
    ///     type T. Note that the type T must match the type T previously set.
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    get_phys(page_pool_storage_t const &store) noexcept -> bsl::safe_u64
    {
        bsl::expects(is_page_pool_storage_set<T>(store));

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, l3t_t>::value) {
            return store.l3t_phys;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, l2t_t>::value) {
            return store.l2t_phys;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, l1t_t>::value) {
            return store.l1t_phys;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, l0t_t>::value) {
            return store.l0t_phys;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, lib::basic_page_4k_t>::value) {
            return store.basic_page_4k_phys;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, lib::basic_page_pool_node_t>::value) {
            return store.basic_page_pool_node_phys;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, mk::ext_tcb_t>::value) {
            return store.ext_tcb_phys;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, mk::vmcb_t>::value) {
            return store.vmcb_phys;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, mk::vmcs_t>::value) {
            return store.vmcs_phys;
        }

        bsl::error() << "not implemented: " << bsl::type_name<T>() << bsl::endl;    // GRCOV_EXCLUDE
        bsl::expects(false);                                                        // GRCOV_EXCLUDE
        return {};                                                                  // GRCOV_EXCLUDE
    }
}

#endif
