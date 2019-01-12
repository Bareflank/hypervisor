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

#include <bfupperlower.h>
#include <memory_manager/arch/x64/cr3/helpers.h>

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

namespace bfvmm::x64::cr3
{

gsl::not_null<mmap *>
vmm_cr3()
{
    static mmap s_mmap;
    return &s_mmap;
}

void
identity_map_1g(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr,
    mmap::attr_type attr,
    mmap::memory_type cache)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pdpt::from) == 0);
    expects(bfn::lower(eaddr, pdpt::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pdpt::page_size) {
        map.map_1g(gpa, gpa, attr, cache);
    }
}

void
identity_map_2m(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr,
    mmap::attr_type attr,
    mmap::memory_type cache)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pd::from) == 0);
    expects(bfn::lower(eaddr, pd::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pd::page_size) {
        map.map_2m(gpa, gpa, attr, cache);
    }
}

void
identity_map_4k(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr,
    mmap::attr_type attr,
    mmap::memory_type cache)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pt::from) == 0);
    expects(bfn::lower(eaddr, pt::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pt::page_size) {
        map.map_4k(gpa, gpa, attr, cache);
    }
}

void
identity_unmap_1g(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pdpt::from) == 0);
    expects(bfn::lower(eaddr, pdpt::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pdpt::page_size) {
        map.unmap(gpa);
    }
}

void
identity_unmap_2m(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pd::from) == 0);
    expects(bfn::lower(eaddr, pd::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pd::page_size) {
        map.unmap(gpa);
    }
}

void
identity_unmap_4k(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pt::from) == 0);
    expects(bfn::lower(eaddr, pt::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pt::page_size) {
        map.unmap(gpa);
    }
}

void
identity_release_1g(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pdpt::from) == 0);
    expects(bfn::lower(eaddr, pdpt::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pdpt::page_size) {
        map.release(gpa);
    }
}

void
identity_release_2m(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pd::from) == 0);
    expects(bfn::lower(eaddr, pd::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pd::page_size) {
        map.release(gpa);
    }
}

void
identity_release_4k(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pt::from) == 0);
    expects(bfn::lower(eaddr, pt::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pt::page_size) {
        map.release(gpa);
    }
}

void
identity_map_convert_1g_to_2m(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr,
    mmap::memory_type cache)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(addr, pdpt::from) == 0);
    expects(map.is_1g(addr));

    map.unmap(addr);

    identity_map_2m(
        map, addr, addr + pdpt::page_size, attr, cache
    );
}

void
identity_map_convert_1g_to_4k(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr,
    mmap::memory_type cache)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(addr, pdpt::from) == 0);
    expects(map.is_1g(addr));

    map.unmap(addr);

    identity_map_4k(
        map, addr, addr + pdpt::page_size, attr, cache
    );
}

void
identity_map_convert_2m_to_1g(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr,
    mmap::memory_type cache)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(addr, pdpt::from) == 0);
    expects(map.is_2m(addr));

    identity_release_2m(
        map, addr, addr + pdpt::page_size
    );

    map.map_1g(addr, addr, attr, cache);
}

void
identity_map_convert_4k_to_1g(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr,
    mmap::memory_type cache)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(addr, pdpt::from) == 0);
    expects(map.is_4k(addr));

    identity_release_4k(
        map, addr, addr + pdpt::page_size
    );

    map.map_1g(addr, addr, attr, cache);
}

void
identity_map_convert_2m_to_4k(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr,
    mmap::memory_type cache)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(addr, pd::from) == 0);
    expects(map.is_2m(addr));

    map.unmap(addr);

    identity_map_4k(
        map, addr, addr + pd::page_size, attr, cache
    );
}

void
identity_map_convert_4k_to_2m(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr,
    mmap::memory_type cache)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(addr, pd::from) == 0);
    expects(map.is_4k(addr));

    identity_release_4k(
        map, addr, addr + pd::page_size
    );

    map.map_2m(addr, addr, attr, cache);
}

}
