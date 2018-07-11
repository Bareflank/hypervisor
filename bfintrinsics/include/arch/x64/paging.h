//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

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
