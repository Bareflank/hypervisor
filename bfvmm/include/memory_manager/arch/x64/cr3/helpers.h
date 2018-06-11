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

#ifndef HELPERS_CR3_X64_H
#define HELPERS_CR3_X64_H

#include "mmap.h"
#include <bfupperlower.h>

namespace bfvmm
{
namespace x64
{
namespace cr3
{

/// Setup Identity Map with 1g Granularity
///
/// @expects
/// @ensures
///
/// @param map the memory map
/// @param virt_addr to the virtual/physical address to start from
/// @param pages the total number of pages to map
/// @param attr the maps permissions
///
inline void
setup_identity_map_1g(
    mmap &map, uintptr_t virt_addr, std::size_t pages,
    mmap::attr_type attr = mmap::attr_type::read_write)
{
    auto saddr = bfn::lower(virt_addr, ::x64::pdpt::from);
    auto eaddr = pages * ::x64::pdpt::page_size;

    for (; saddr < eaddr; saddr += ::x64::pdpt::page_size) {
        map.map_1g(saddr, saddr);
    }
}

/// Setup Identity Map with 1g Granularity
///
/// @expects
/// @ensures
///
/// @param map the memory map
/// @param virt_addr to the virtual/physical address to start from
/// @param pages the total number of pages to map
/// @param attr the maps permissions
///
inline void
setup_identity_map_1g(
    mmap &map, mmap::virt_addr_t virt_addr, std::size_t pages,
    mmap::attr_type attr = mmap::attr_type::read_write)
{
    setup_identity_map_1g(
        map, reinterpret_cast<uintptr_t>(virt_addr), pages, attr
    );
}

/// Setup Identity Map with 2m Granularity
///
/// @expects
/// @ensures
///
/// @param map the memory map
/// @param virt_addr to the virtual/physical address to start from
/// @param pages the total number of pages to map
/// @param attr the maps permissions
///
inline void
setup_identity_map_2m(
    mmap &map, uintptr_t virt_addr, std::size_t pages,
    mmap::attr_type attr = mmap::attr_type::read_write)
{
    auto saddr = bfn::lower(virt_addr, ::x64::pd::from);
    auto eaddr = pages * ::x64::pd::page_size;

    for (; saddr < eaddr; saddr += ::x64::pd::page_size) {
        map.map_2m(saddr, saddr);
    }
}

/// Setup Identity Map with 2m Granularity
///
/// @expects
/// @ensures
///
/// @param map the memory map
/// @param virt_addr to the virtual/physical address to start from
/// @param pages the total number of pages to map
/// @param attr the maps permissions
///
inline void
setup_identity_map_2m(
    mmap &map, mmap::virt_addr_t virt_addr, std::size_t pages,
    mmap::attr_type attr = mmap::attr_type::read_write)
{
    setup_identity_map_2m(
        map, reinterpret_cast<uintptr_t>(virt_addr), pages, attr
    );
}

/// Setup Identity Map with 4k Granularity
///
/// @expects
/// @ensures
///
/// @param map the memory map
/// @param virt_addr to the virtual/physical address to start from
/// @param pages the total number of pages to map
/// @param attr the maps permissions
///
inline void
setup_identity_map_4k(
    mmap &map, uintptr_t virt_addr, std::size_t pages,
    mmap::attr_type attr = mmap::attr_type::read_write)
{
    auto saddr = bfn::lower(virt_addr, ::x64::pt::from);
    auto eaddr = pages * ::x64::pt::page_size;

    for (; saddr < eaddr; saddr += ::x64::pt::page_size) {
        map.map_4k(saddr, saddr);
    }
}

/// Setup Identity Map with 4k Granularity
///
/// @expects
/// @ensures
///
/// @param map the memory map
/// @param virt_addr to the virtual/physical address to start from
/// @param pages the total number of pages to map
/// @param attr the maps permissions
///
inline void
setup_identity_map_4k(
    mmap &map, mmap::virt_addr_t virt_addr, std::size_t pages,
    mmap::attr_type attr = mmap::attr_type::read_write)
{
    setup_identity_map_4k(
        map, reinterpret_cast<uintptr_t>(virt_addr), pages, attr
    );
}

}
}
}

#endif
