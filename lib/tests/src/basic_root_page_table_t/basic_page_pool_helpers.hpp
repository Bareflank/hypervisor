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
#include <l0e_t.hpp>
#include <l1e_t.hpp>
#include <l2e_t.hpp>
#include <l3e_t.hpp>

#include <bsl/unordered_map.hpp>

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
    ///   @brief Stores which type of pointer the virt_storage_type_t is
    ///     currently storing.
    ///
    // NOLINTNEXTLINE(bsl-user-defined-type-names-match-header-name)
    enum class virt_storage_type_t : bsl::uint64
    {
        /// @brief states that the storage is empty (required)
        none,
        /// @brief set when the type is a l3t_t
        l3t,
        /// @brief set when the type is a l2t_t
        l2t,
        /// @brief set when the type is a l1t_t
        l1t,
        /// @brief set when the type is a l0t_t
        l0t,
        /// @brief set when the type is a l3e_t
        l3e,
        /// @brief set when the type is a l2e_t
        l2e,
        /// @brief set when the type is a l1e_t
        l1e,
        /// @brief set when the type is a l0e_t
        l0e,
        /// @brief set when the type is a basic_page_4k_t
        basic_page_4k,
    };

    /// @struct helpers::virt_storage_t
    ///
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
    struct virt_storage_t final
    {
        /// @brief stores which type the union is
        virt_storage_type_t type;

        union
        {
            /// @brief store a l3t_t pointer
            l3t_t *l3t_ptr;    // NOLINT
            /// @brief store a l2t_t pointer
            l2t_t *l2t_ptr;    // NOLINT
            /// @brief store a l1t_t pointer
            l1t_t *l1t_ptr;    // NOLINT
            /// @brief store a l0t_t pointer
            l0t_t *l0t_ptr;    // NOLINT
            /// @brief store a l3e_t pointer
            lib::l3e_t *l3e_ptr;    // NOLINT
            /// @brief store a l2e_t pointer
            lib::l2e_t *l2e_ptr;    // NOLINT
            /// @brief store a l1e_t pointer
            lib::l1e_t *l1e_ptr;    // NOLINT
            /// @brief store a l0e_t pointer
            lib::l0e_t *l0e_ptr;    // NOLINT
            /// @brief store a basic_page_4k_t pointer
            lib::basic_page_4k_t *basic_page_4k_ptr;    // NOLINT
        };
    };

    /// <!-- description -->
    ///   @brief Sets the phys to virt translation in the provided map based
    ///     on the provided type T.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of virtual address to store
    ///   @param mut_store the virt_storage_t to store the pointer in
    ///   @param pmut_virt the virtual address to store
    ///
    template<typename T>
    constexpr void
    set_virt(virt_storage_t &mut_store, T *const pmut_virt) noexcept
    {
        if constexpr (bsl::is_same<T, l3t_t>::value) {
            mut_store.type = virt_storage_type_t::l3t;
            mut_store.l3t_ptr = pmut_virt;
            return;
        }

        if constexpr (bsl::is_same<T, l2t_t>::value) {
            mut_store.type = virt_storage_type_t::l2t;
            mut_store.l2t_ptr = pmut_virt;
            return;
        }

        if constexpr (bsl::is_same<T, l1t_t>::value) {
            mut_store.type = virt_storage_type_t::l1t;
            mut_store.l1t_ptr = pmut_virt;
            return;
        }

        if constexpr (bsl::is_same<T, l0t_t>::value) {
            mut_store.type = virt_storage_type_t::l0t;
            mut_store.l0t_ptr = pmut_virt;
            return;
        }

        if constexpr (bsl::is_same<T, lib::l3e_t>::value) {
            mut_store.type = virt_storage_type_t::l3e;
            mut_store.l3e_ptr = pmut_virt;
            return;
        }

        if constexpr (bsl::is_same<T, lib::l2e_t>::value) {
            mut_store.type = virt_storage_type_t::l2e;
            mut_store.l2e_ptr = pmut_virt;
            return;
        }

        if constexpr (bsl::is_same<T, lib::l1e_t>::value) {
            mut_store.type = virt_storage_type_t::l1e;
            mut_store.l1e_ptr = pmut_virt;
            return;
        }

        if constexpr (bsl::is_same<T, lib::l0e_t>::value) {
            mut_store.type = virt_storage_type_t::l0e;
            mut_store.l0e_ptr = pmut_virt;
            return;
        }

        if constexpr (bsl::is_same<T, lib::basic_page_4k_t>::value) {
            mut_store.type = virt_storage_type_t::basic_page_4k;
            mut_store.basic_page_4k_ptr = pmut_virt;
            return;
        }
    }

    /// <!-- description -->
    ///   @brief Returns true if the virt_storage_t is of type T. Returns
    ///     false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T type type to query
    ///   @param store the virt_storage_t to query
    ///   @return Returns true if the virt_storage_t is of type T. Returns
    ///     false otherwise.
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    is_virt_a_t(virt_storage_t const &store) noexcept -> bool
    {
        if constexpr (bsl::is_same<T, l3t_t>::value) {
            return store.type == virt_storage_type_t::l3t;
        }

        if constexpr (bsl::is_same<T, l2t_t>::value) {
            return store.type == virt_storage_type_t::l2t;
        }

        if constexpr (bsl::is_same<T, l1t_t>::value) {
            return store.type == virt_storage_type_t::l1t;
        }

        if constexpr (bsl::is_same<T, l0t_t>::value) {
            return store.type == virt_storage_type_t::l0t;
        }

        if constexpr (bsl::is_same<T, lib::l3e_t>::value) {
            return store.type == virt_storage_type_t::l3e;
        }

        if constexpr (bsl::is_same<T, lib::l2e_t>::value) {
            return store.type == virt_storage_type_t::l2e;
        }

        if constexpr (bsl::is_same<T, lib::l1e_t>::value) {
            return store.type == virt_storage_type_t::l1e;
        }

        if constexpr (bsl::is_same<T, lib::l0e_t>::value) {
            return store.type == virt_storage_type_t::l0e;
        }

        if constexpr (bsl::is_same<T, lib::basic_page_4k_t>::value) {
            return store.type == virt_storage_type_t::basic_page_4k;
        }

        return false;
    }

    /// <!-- description -->
    ///   @brief Returns a previously stored pointer based on the provided
    ///     type T. Note that the type T must match the type T previously set.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of virtual address to get
    ///   @return Returns a previously stored pointer based on the provided
    ///     type T. Note that the type T must match the type T previously set.
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    get_virt(virt_storage_t const &store) noexcept -> T *
    {
        bsl::expects(is_virt_a_t<T>(store));

        if constexpr (bsl::is_same<T, l3t_t>::value) {
            return store.l3t_ptr;
        }

        if constexpr (bsl::is_same<T, l2t_t>::value) {
            return store.l2t_ptr;
        }

        if constexpr (bsl::is_same<T, l1t_t>::value) {
            return store.l1t_ptr;
        }

        if constexpr (bsl::is_same<T, l0t_t>::value) {
            return store.l0t_ptr;
        }

        if constexpr (bsl::is_same<T, lib::l3e_t>::value) {
            return store.l3e_ptr;
        }

        if constexpr (bsl::is_same<T, lib::l2e_t>::value) {
            return store.l2e_ptr;
        }

        if constexpr (bsl::is_same<T, lib::l1e_t>::value) {
            return store.l1e_ptr;
        }

        if constexpr (bsl::is_same<T, lib::l0e_t>::value) {
            return store.l0e_ptr;
        }

        if constexpr (bsl::is_same<T, lib::basic_page_4k_t>::value) {
            return store.basic_page_4k_ptr;
        }
    }
}

#endif
