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

#ifndef PAGING_X64_H
#define PAGING_X64_H

#include <bfdebug.h>
#include <bfbitmanip.h>

#include <arch/x64/cpuid.h>

// *INDENT-OFF*

namespace x64
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

        namespace present
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "present";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace rw
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1ULL;
            constexpr const auto name = "rw";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace us
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2ULL;
            constexpr const auto name = "us";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace pwt
        {
            constexpr const auto mask = 0x0000000000000008ULL;
            constexpr const auto from = 3ULL;
            constexpr const auto name = "pwt";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace pcd
        {
            constexpr const auto mask = 0x0000000000000010ULL;
            constexpr const auto from = 4ULL;
            constexpr const auto name = "pcd";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace accessed
        {
            constexpr const auto mask = 0x0000000000000020ULL;
            constexpr const auto from = 5ULL;
            constexpr const auto name = "accessed";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

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

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }
        }

        namespace phys_addr
        {
            constexpr const auto mask = 0x000FFFFFFFFFF000ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "phys_addr";

            inline auto get(value_type entry) noexcept
            { return get_bits(entry, mask) >> from; }

            inline void set(value_type &entry, value_type val) noexcept
            { entry = set_bits(entry, mask, val << from); }
        }

        namespace xd
        {
            constexpr const auto mask = 0x8000000000000000ULL;
            constexpr const auto from = 63ULL;
            constexpr const auto name = "xd";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace pat_index
        {
            using value_type = uint64_t;

            inline auto get(value_type entry) noexcept
            {
                value_type index = 0;

                if (pwt::is_enabled(entry)) {
                    index += 1;
                }

                if (pcd::is_enabled(entry)) {
                    index += 2;
                }

                return index;
            }

            inline void set(value_type &entry, value_type index) noexcept
            {
                switch (index) {
                    case 0:
                        pwt::disable(entry);
                        pcd::disable(entry);
                        break;

                    case 1:
                        pwt::enable(entry);
                        pcd::disable(entry);
                        break;

                    case 2:
                        pwt::disable(entry);
                        pcd::enable(entry);
                        break;

                    default:
                        pwt::enable(entry);
                        pcd::enable(entry);
                        break;
                };
            }
        }
    }
}

namespace pdpt
{
    constexpr const auto num_entries = 512;

    constexpr const auto from = 30U;
    constexpr const auto size = num_entries * sizeof(uintptr_t);

    constexpr const auto page_size = 0x40000000ULL;
    constexpr const auto page_shift = 30;

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

        namespace present
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "present";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace rw
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1ULL;
            constexpr const auto name = "rw";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace us
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2ULL;
            constexpr const auto name = "us";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace pwt
        {
            constexpr const auto mask = 0x0000000000000008ULL;
            constexpr const auto from = 3ULL;
            constexpr const auto name = "pwt";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace pcd
        {
            constexpr const auto mask = 0x0000000000000010ULL;
            constexpr const auto from = 4ULL;
            constexpr const auto name = "pcd";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace accessed
        {
            constexpr const auto mask = 0x0000000000000020ULL;
            constexpr const auto from = 5ULL;
            constexpr const auto name = "accessed";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace dirty
        {
            constexpr const auto mask = 0x0000000000000040ULL;
            constexpr const auto from = 6ULL;
            constexpr const auto name = "dirty";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

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

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace g
        {
            constexpr const auto mask = 0x0000000000000100ULL;
            constexpr const auto from = 8ULL;
            constexpr const auto name = "g";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace pat
        {
            constexpr const auto mask = 0x0000000000001000ULL;
            constexpr const auto from = 12ULL;
            constexpr const auto name = "pat";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace phys_addr
        {
            constexpr const auto mask = 0x000FFFFFFFFFF000ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "phys_addr";

            inline auto get(value_type entry) noexcept
            { return get_bits(entry, mask) >> from; }

            inline void set(value_type &entry, value_type val) noexcept
            { entry = set_bits(entry, mask, val << from); }
        }

        namespace protection_key
        {
            constexpr const auto mask = 0x7800000000000000ULL;
            constexpr const auto from = 59ULL;
            constexpr const auto name = "protection_key";

            inline auto get(value_type entry) noexcept
            { return get_bits(entry, mask) >> from; }

            inline void set(value_type &entry, value_type val) noexcept
            { entry = set_bits(entry, mask, val << from); }
        }

        namespace xd
        {
            constexpr const auto mask = 0x8000000000000000ULL;
            constexpr const auto from = 63ULL;
            constexpr const auto name = "xd";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace pat_index
        {
            using value_type = uint64_t;

            inline auto get(value_type entry) noexcept
            {
                value_type index = 0;

                if (pwt::is_enabled(entry)) {
                    index += 1;
                }

                if (pcd::is_enabled(entry)) {
                    index += 2;
                }

                if (ps::is_enabled(entry)) {
                    if (pat::is_enabled(entry)) {
                        index += 4;
                    }
                }

                return index;
            }

            inline void set(value_type &entry, value_type index) noexcept
            {
                if (ps::is_enabled(entry)) {
                    switch (index) {
                        case 0:
                            pwt::disable(entry);
                            pcd::disable(entry);
                            pat::disable(entry);
                            break;

                        case 1:
                            pwt::enable(entry);
                            pcd::disable(entry);
                            pat::disable(entry);
                            break;

                        case 2:
                            pwt::disable(entry);
                            pcd::enable(entry);
                            pat::disable(entry);
                            break;

                        case 3:
                            pwt::enable(entry);
                            pcd::enable(entry);
                            pat::disable(entry);
                            break;

                        case 4:
                            pwt::disable(entry);
                            pcd::disable(entry);
                            pat::enable(entry);
                            break;

                        case 5:
                            pwt::enable(entry);
                            pcd::disable(entry);
                            pat::enable(entry);
                            break;

                        case 6:
                            pwt::disable(entry);
                            pcd::enable(entry);
                            pat::enable(entry);
                            break;

                        default:
                            pwt::enable(entry);
                            pcd::enable(entry);
                            pat::enable(entry);
                            break;
                    };
                }
                else {
                    switch (index) {
                        case 0:
                            pwt::disable(entry);
                            pcd::disable(entry);
                            break;

                        case 1:
                            pwt::enable(entry);
                            pcd::disable(entry);
                            break;

                        case 2:
                            pwt::disable(entry);
                            pcd::enable(entry);
                            break;

                        default:
                            pwt::enable(entry);
                            pcd::enable(entry);
                            break;
                    };
                }
            }
        }

        namespace reserved
        {
            constexpr const auto from = 0ULL;
            constexpr const auto name = "reserved";

            inline auto mask() noexcept
            { return ((0xFFFFFFFFFFFFFFFFULL << cpuid::addr_size::phys::get()) | 0x1E6ULL); }
        }
    }
}

namespace pd
{
    constexpr const auto num_entries = 512;

    constexpr const auto from = 21U;
    constexpr const auto size = num_entries * sizeof(uintptr_t);

    constexpr const auto page_size = 0x200000ULL;
    constexpr const auto page_shift = 21;

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

        namespace present
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "present";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace rw
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1ULL;
            constexpr const auto name = "rw";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace us
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2ULL;
            constexpr const auto name = "us";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace pwt
        {
            constexpr const auto mask = 0x0000000000000008ULL;
            constexpr const auto from = 3ULL;
            constexpr const auto name = "pwt";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace pcd
        {
            constexpr const auto mask = 0x0000000000000010ULL;
            constexpr const auto from = 4ULL;
            constexpr const auto name = "pcd";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace accessed
        {
            constexpr const auto mask = 0x0000000000000020ULL;
            constexpr const auto from = 5ULL;
            constexpr const auto name = "accessed";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace dirty
        {
            constexpr const auto mask = 0x0000000000000040ULL;
            constexpr const auto from = 6ULL;
            constexpr const auto name = "dirty";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

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

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace g
        {
            constexpr const auto mask = 0x0000000000000100ULL;
            constexpr const auto from = 8ULL;
            constexpr const auto name = "g";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace pat
        {
            constexpr const auto mask = 0x0000000000001000ULL;
            constexpr const auto from = 12ULL;
            constexpr const auto name = "pat";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace phys_addr
        {
            constexpr const auto mask = 0x000FFFFFFFFFF000ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "phys_addr";

            inline auto get(value_type entry) noexcept
            { return get_bits(entry, mask) >> from; }

            inline void set(value_type &entry, value_type val) noexcept
            { entry = set_bits(entry, mask, val << from); }
        }

        namespace protection_key
        {
            constexpr const auto mask = 0x7800000000000000ULL;
            constexpr const auto from = 59ULL;
            constexpr const auto name = "protection_key";

            inline auto get(value_type entry) noexcept
            { return get_bits(entry, mask) >> from; }

            inline void set(value_type &entry, value_type val) noexcept
            { entry = set_bits(entry, mask, val << from); }
        }

        namespace xd
        {
            constexpr const auto mask = 0x8000000000000000ULL;
            constexpr const auto from = 63ULL;
            constexpr const auto name = "xd";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace pat_index
        {
            using value_type = uint64_t;

            inline auto get(value_type entry) noexcept
            {
                value_type index = 0;

                if (pwt::is_enabled(entry)) {
                    index += 1;
                }

                if (pcd::is_enabled(entry)) {
                    index += 2;
                }

                if (ps::is_enabled(entry)) {
                    if (pat::is_enabled(entry)) {
                        index += 4;
                    }
                }

                return index;
            }

            inline void set(value_type &entry, value_type index) noexcept
            {
                if (ps::is_enabled(entry)) {
                    switch (index) {
                        case 0:
                            pwt::disable(entry);
                            pcd::disable(entry);
                            pat::disable(entry);
                            break;

                        case 1:
                            pwt::enable(entry);
                            pcd::disable(entry);
                            pat::disable(entry);
                            break;

                        case 2:
                            pwt::disable(entry);
                            pcd::enable(entry);
                            pat::disable(entry);
                            break;

                        case 3:
                            pwt::enable(entry);
                            pcd::enable(entry);
                            pat::disable(entry);
                            break;

                        case 4:
                            pwt::disable(entry);
                            pcd::disable(entry);
                            pat::enable(entry);
                            break;

                        case 5:
                            pwt::enable(entry);
                            pcd::disable(entry);
                            pat::enable(entry);
                            break;

                        case 6:
                            pwt::disable(entry);
                            pcd::enable(entry);
                            pat::enable(entry);
                            break;

                        default:
                            pwt::enable(entry);
                            pcd::enable(entry);
                            pat::enable(entry);
                            break;
                    };
                }
                else {
                    switch (index) {
                        case 0:
                            pwt::disable(entry);
                            pcd::disable(entry);
                            break;

                        case 1:
                            pwt::enable(entry);
                            pcd::disable(entry);
                            break;

                        case 2:
                            pwt::disable(entry);
                            pcd::enable(entry);
                            break;

                        default:
                            pwt::enable(entry);
                            pcd::enable(entry);
                            break;
                    };
                }
            }
        }
    }
}

namespace pt
{
    constexpr const auto num_entries = 512;

    constexpr const auto from = 12U;
    constexpr const auto size = num_entries * sizeof(uintptr_t);

    constexpr const auto page_size = 0x1000ULL;
    constexpr const auto page_shift = 12;

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

        namespace present
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "present";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace rw
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1ULL;
            constexpr const auto name = "rw";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace us
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2ULL;
            constexpr const auto name = "us";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace pwt
        {
            constexpr const auto mask = 0x0000000000000008ULL;
            constexpr const auto from = 3ULL;
            constexpr const auto name = "pwt";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace pcd
        {
            constexpr const auto mask = 0x0000000000000010ULL;
            constexpr const auto from = 4ULL;
            constexpr const auto name = "pcd";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace accessed
        {
            constexpr const auto mask = 0x0000000000000020ULL;
            constexpr const auto from = 5ULL;
            constexpr const auto name = "accessed";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace dirty
        {
            constexpr const auto mask = 0x0000000000000040ULL;
            constexpr const auto from = 6ULL;
            constexpr const auto name = "dirty";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace pat
        {
            constexpr const auto mask = 0x0000000000000080ULL;
            constexpr const auto from = 7ULL;
            constexpr const auto name = "pat";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace g
        {
            constexpr const auto mask = 0x0000000000000100ULL;
            constexpr const auto from = 8ULL;
            constexpr const auto name = "g";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace phys_addr
        {
            constexpr const auto mask = 0x000FFFFFFFFFF000ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "phys_addr";

            inline auto get(value_type entry) noexcept
            { return get_bits(entry, mask) >> from; }

            inline void set(value_type &entry, value_type val) noexcept
            { entry = set_bits(entry, mask, val << from); }
        }

        namespace protection_key
        {
            constexpr const auto mask = 0x7800000000000000ULL;
            constexpr const auto from = 59ULL;
            constexpr const auto name = "protection_key";

            inline auto get(value_type entry) noexcept
            { return get_bits(entry, mask) >> from; }

            inline void set(value_type &entry, value_type val) noexcept
            { entry = set_bits(entry, mask, val << from); }
        }

        namespace xd
        {
            constexpr const auto mask = 0x8000000000000000ULL;
            constexpr const auto from = 63ULL;
            constexpr const auto name = "xd";

            inline auto is_enabled(value_type entry) noexcept
            { return is_bit_set(entry, from); }

            inline auto is_disabled(value_type entry) noexcept
            { return is_bit_cleared(entry, from); }

            inline void enable(value_type &entry) noexcept
            { entry = set_bit(entry, from); }

            inline void disable(value_type &entry) noexcept
            { entry = clear_bit(entry, from); }
        }

        namespace pat_index
        {
            using value_type = uint64_t;

            inline auto get(value_type entry) noexcept
            {
                value_type index = 0;

                if (pwt::is_enabled(entry)) {
                    index += 1;
                }

                if (pcd::is_enabled(entry)) {
                    index += 2;
                }

                if (pat::is_enabled(entry)) {
                    index += 4;
                }

                return index;
            }

            inline void set(value_type &entry, value_type index) noexcept
            {
                switch (index) {
                    case 0:
                        pwt::disable(entry);
                        pcd::disable(entry);
                        pat::disable(entry);
                        break;

                    case 1:
                        pwt::enable(entry);
                        pcd::disable(entry);
                        pat::disable(entry);
                        break;

                    case 2:
                        pwt::disable(entry);
                        pcd::enable(entry);
                        pat::disable(entry);
                        break;

                    case 3:
                        pwt::enable(entry);
                        pcd::enable(entry);
                        pat::disable(entry);
                        break;

                    case 4:
                        pwt::disable(entry);
                        pcd::disable(entry);
                        pat::enable(entry);
                        break;

                    case 5:
                        pwt::enable(entry);
                        pcd::disable(entry);
                        pat::enable(entry);
                        break;

                    case 6:
                        pwt::disable(entry);
                        pcd::enable(entry);
                        pat::enable(entry);
                        break;

                    default:
                        pwt::enable(entry);
                        pcd::enable(entry);
                        pat::enable(entry);
                        break;
                };
            }
        }
    }
}

}

// *INDENT-ON*

#endif
