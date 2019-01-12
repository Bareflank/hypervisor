//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef EPT_INTEL_X64_H
#define EPT_INTEL_X64_H

#include <bfdebug.h>
#include <bfbitmanip.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace ept
{

namespace pml4
{
    constexpr const auto num_entries = 512;

    constexpr const auto from = 39U;
    constexpr const auto size = num_entries * sizeof(uintptr_t);

    inline auto index(uintptr_t virt)
    {
        return gsl::narrow_cast<std::ptrdiff_t>(
            (virt & ((0x1FFULL) << from)) >> from
        );
    }

    template<
        typename T,
        typename = std::enable_if<std::is_pointer<T>::value >
        >
    auto index(T virt)
    { return index(reinterpret_cast<uintptr_t>(virt)); }

    namespace entry
    {
        using value_type = uint64_t;

        namespace read_access
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "read_access";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace write_access
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1ULL;
            constexpr const auto name = "write_access";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace execute_access
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2ULL;
            constexpr const auto name = "execute_access";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace accessed_flag
        {
            constexpr const auto mask = 0x0000000000000100ULL;
            constexpr const auto from = 8ULL;
            constexpr const auto name = "accessed_flag";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace execute_access_user
        {
            constexpr const auto mask = 0x0000000000000400ULL;
            constexpr const auto from = 10ULL;
            constexpr const auto name = "execute_access_user";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace phys_addr
        {
            constexpr const auto mask = 0x0000FFFFFFFFF000ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "phys_addr";

            inline auto get(value_type &entry) noexcept
            { return get_bits(entry, mask) >> from; }

            inline void set(value_type &entry, value_type val) noexcept
            { entry = set_bits(entry, mask, val << from); }
        }

        namespace suppress_ve
        {
            constexpr const auto mask = 0x8000000000000000ULL;
            constexpr const auto from = 63ULL;
            constexpr const auto name = "suppress_ve";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }
    }
}

namespace pdpt
{
    constexpr const auto num_entries = 512;

    constexpr const auto from = 30U;
    constexpr const auto size = num_entries * sizeof(uintptr_t);

    constexpr const auto page_size = 0x40000000ULL;

    inline auto index(uintptr_t virt)
    {
        return gsl::narrow_cast<std::ptrdiff_t>(
            (virt & ((0x1FFULL) << from)) >> from
        );
    }

    template<
        typename T,
        typename = std::enable_if<std::is_pointer<T>::value >
        >
    auto index(T virt)
    { return index(reinterpret_cast<uintptr_t>(virt)); }

    namespace entry
    {
        using value_type = uint64_t;

        namespace read_access
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "read_access";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace write_access
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1ULL;
            constexpr const auto name = "write_access";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace execute_access
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2ULL;
            constexpr const auto name = "execute_access";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace memory_type
        {
            constexpr const auto mask = 0x0000000000000038ULL;
            constexpr const auto from = 3ULL;
            constexpr const auto name = "memory_type";

            constexpr const auto uncacheable = 0x0ULL;
            constexpr const auto write_combining = 0x1ULL;
            constexpr const auto write_through = 0x4ULL;
            constexpr const auto write_protected = 0x5ULL;
            constexpr const auto write_back = 0x6ULL;

            inline auto get(value_type &entry) noexcept
            { return get_bits(entry, mask) >> from; }

            inline void set(value_type &entry, value_type val) noexcept
            { entry = set_bits(entry, mask, val << from); }
        }

        namespace ignore_pat
        {
            constexpr const auto mask = 0x0000000000000040ULL;
            constexpr const auto from = 6ULL;
            constexpr const auto name = "ignore_pat";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace ps
        {
            constexpr const auto mask = 0x0000000000000080ULL;
            constexpr const auto from = 7ULL;
            constexpr const auto name = "ps";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace accessed_flag
        {
            constexpr const auto mask = 0x0000000000000100ULL;
            constexpr const auto from = 8ULL;
            constexpr const auto name = "accessed_flag";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace dirty
        {
            constexpr const auto mask = 0x0000000000000200ULL;
            constexpr const auto from = 9ULL;
            constexpr const auto name = "dirty";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace execute_access_user
        {
            constexpr const auto mask = 0x0000000000000400ULL;
            constexpr const auto from = 10ULL;
            constexpr const auto name = "execute_access_user";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace phys_addr
        {
            constexpr const auto mask = 0x0000FFFFFFFFF000ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "phys_addr";

            inline auto get(value_type &entry) noexcept
            { return get_bits(entry, mask) >> from; }

            inline void set(value_type &entry, value_type val) noexcept
            { entry = set_bits(entry, mask, val << from); }
        }

        namespace suppress_ve
        {
            constexpr const auto mask = 0x8000000000000000ULL;
            constexpr const auto from = 63ULL;
            constexpr const auto name = "suppress_ve";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }
    }
}

namespace pd
{
    constexpr const auto num_entries = 512;

    constexpr const auto from = 21U;
    constexpr const auto size = num_entries * sizeof(uintptr_t);

    constexpr const auto page_size = 0x200000ULL;

    inline auto index(uintptr_t virt)
    {
        return gsl::narrow_cast<std::ptrdiff_t>(
            (virt & ((0x1FFULL) << from)) >> from
        );
    }

    template<
        typename T,
        typename = std::enable_if<std::is_pointer<T>::value >
        >
    auto index(T virt)
    { return index(reinterpret_cast<uintptr_t>(virt)); }

    namespace entry
    {
        using value_type = uint64_t;

        namespace read_access
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "read_access";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace write_access
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1ULL;
            constexpr const auto name = "write_access";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace execute_access
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2ULL;
            constexpr const auto name = "execute_access";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace memory_type
        {
            constexpr const auto mask = 0x0000000000000038ULL;
            constexpr const auto from = 3ULL;
            constexpr const auto name = "memory_type";

            constexpr const auto uncacheable = 0x0ULL;
            constexpr const auto write_combining = 0x1ULL;
            constexpr const auto write_through = 0x4ULL;
            constexpr const auto write_protected = 0x5ULL;
            constexpr const auto write_back = 0x6ULL;

            inline auto get(value_type &entry) noexcept
            { return get_bits(entry, mask) >> from; }

            inline void set(value_type &entry, value_type val) noexcept
            { entry = set_bits(entry, mask, val << from); }
        }

        namespace ignore_pat
        {
            constexpr const auto mask = 0x0000000000000040ULL;
            constexpr const auto from = 6ULL;
            constexpr const auto name = "ignore_pat";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace ps
        {
            constexpr const auto mask = 0x0000000000000080ULL;
            constexpr const auto from = 7ULL;
            constexpr const auto name = "ps";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace accessed_flag
        {
            constexpr const auto mask = 0x0000000000000100ULL;
            constexpr const auto from = 8ULL;
            constexpr const auto name = "accessed_flag";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace dirty
        {
            constexpr const auto mask = 0x0000000000000200ULL;
            constexpr const auto from = 9ULL;
            constexpr const auto name = "dirty";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace execute_access_user
        {
            constexpr const auto mask = 0x0000000000000400ULL;
            constexpr const auto from = 10ULL;
            constexpr const auto name = "execute_access_user";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace phys_addr
        {
            constexpr const auto mask = 0x0000FFFFFFFFF000ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "phys_addr";

            inline auto get(value_type &entry) noexcept
            { return get_bits(entry, mask) >> from; }

            inline void set(value_type &entry, value_type val) noexcept
            { entry = set_bits(entry, mask, val << from); }
        }

        namespace suppress_ve
        {
            constexpr const auto mask = 0x8000000000000000ULL;
            constexpr const auto from = 63ULL;
            constexpr const auto name = "suppress_ve";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }
    }
}

namespace pt
{
    constexpr const auto num_entries = 512;

    constexpr const auto from = 12U;
    constexpr const auto size = num_entries * sizeof(uintptr_t);

    constexpr const auto page_size = 0x1000ULL;

    inline auto index(uintptr_t virt)
    {
        return gsl::narrow_cast<std::ptrdiff_t>(
            (virt & ((0x1FFULL) << from)) >> from
        );
    }

    template<
        typename T,
        typename = std::enable_if<std::is_pointer<T>::value >
        >
    auto index(T virt)
    { return index(reinterpret_cast<uintptr_t>(virt)); }

    namespace entry
    {
        using value_type = uint64_t;

        namespace read_access
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "read_access";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace write_access
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1ULL;
            constexpr const auto name = "write_access";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace execute_access
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2ULL;
            constexpr const auto name = "execute_access";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace memory_type
        {
            constexpr const auto mask = 0x0000000000000038ULL;
            constexpr const auto from = 3ULL;
            constexpr const auto name = "memory_type";

            constexpr const auto uncacheable = 0x0ULL;
            constexpr const auto write_combining = 0x1ULL;
            constexpr const auto write_through = 0x4ULL;
            constexpr const auto write_protected = 0x5ULL;
            constexpr const auto write_back = 0x6ULL;

            inline auto get(value_type &entry) noexcept
            { return get_bits(entry, mask) >> from; }

            inline void set(value_type &entry, value_type val) noexcept
            { entry = set_bits(entry, mask, val << from); }
        }

        namespace ignore_pat
        {
            constexpr const auto mask = 0x0000000000000040ULL;
            constexpr const auto from = 6ULL;
            constexpr const auto name = "ignore_pat";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace ps
        {
            constexpr const auto mask = 0x0000000000000080ULL;
            constexpr const auto from = 7ULL;
            constexpr const auto name = "ps";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace accessed_flag
        {
            constexpr const auto mask = 0x0000000000000100ULL;
            constexpr const auto from = 8ULL;
            constexpr const auto name = "accessed_flag";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace dirty
        {
            constexpr const auto mask = 0x0000000000000200ULL;
            constexpr const auto from = 9ULL;
            constexpr const auto name = "dirty";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace execute_access_user
        {
            constexpr const auto mask = 0x0000000000000400ULL;
            constexpr const auto from = 10ULL;
            constexpr const auto name = "execute_access_user";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace phys_addr
        {
            constexpr const auto mask = 0x0000FFFFFFFFF000ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "phys_addr";

            inline auto get(value_type &entry) noexcept
            { return get_bits(entry, mask) >> from; }

            inline void set(value_type &entry, value_type val) noexcept
            { entry = set_bits(entry, mask, val << from); }
        }

        namespace suppress_ve
        {
            constexpr const auto mask = 0x8000000000000000ULL;
            constexpr const auto from = 63ULL;
            constexpr const auto name = "suppress_ve";

            inline auto is_enabled(value_type &entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type &entry) noexcept
            { return !is_bit_set(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }
    }
}

}
}

// *INDENT-ON*

#endif
