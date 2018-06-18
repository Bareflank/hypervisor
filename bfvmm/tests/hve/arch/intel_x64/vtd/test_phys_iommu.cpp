//
// Bareflank Extended APIs
//
// Copyright (C) 2018 Assured Information Security, Inc.
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

// TIDY_EXCLUSION=-cppcoreguidelines-pro*
//
// Reason:
//     This triggers on g_iommu_base which is only used for testing.
//

#include <catch/catch.hpp>
#include <hve/arch/intel_x64/vtd/phys_iommu.h>

uint32_t g_iommu[0x400] = {0U};
uintptr_t g_iommu_base = reinterpret_cast<uintptr_t>(g_iommu);

TEST_CASE("phys_iommu: construct")
{
    auto iommu = ::intel_x64::vtd::phys_iommu(g_iommu_base);
    CHECK(iommu.m_base == g_iommu_base);
}

TEST_CASE("phys_iommu: read_32")
{
    auto iommu = ::intel_x64::vtd::phys_iommu(g_iommu_base);

    g_iommu[0] = 0;
    CHECK(iommu.read_32(0) == 0);

    g_iommu[0] = 0xF00DBEEF;
    CHECK(iommu.read_32(0) == 0xF00DBEEF);
}

TEST_CASE("phys_iommu: read_64")
{
    auto iommu = ::intel_x64::vtd::phys_iommu(g_iommu_base);

    g_iommu[0] = 0;
    g_iommu[1] = 0;
    CHECK(iommu.read_64(0) == 0);

    g_iommu[0] = 0xF00DBEEF;
    g_iommu[1] = 0xBADC0FFE;
    CHECK(iommu.read_64(0) == 0xBADC0FFEF00DBEEF);
}

TEST_CASE("phys_iommu: write_32")
{
    auto iommu = ::intel_x64::vtd::phys_iommu(g_iommu_base);

    g_iommu[0] = 0;
    iommu.write_32(0, 0xF00DBEEF);
    CHECK(g_iommu[0] == 0xF00DBEEF);

    iommu.write_32(0, 0);
    CHECK(g_iommu[0] == 0);
}

TEST_CASE("phys_iommu: write_32_preserved")
{
    auto iommu = ::intel_x64::vtd::phys_iommu(g_iommu_base);

    g_iommu[0] = 0xFFFFFFFF;
    iommu.write_32_preserved(0, 0, 0xFF00FF00);
    CHECK(g_iommu[0] == 0xFF00FF00);
}

TEST_CASE("phys_iommu: write_64")
{
    auto iommu = ::intel_x64::vtd::phys_iommu(g_iommu_base);

    g_iommu[0] = 0;
    g_iommu[1] = 0;
    iommu.write_64(0, 0xBADC0FFEF00DBEEF);
    CHECK(g_iommu[0] == 0xF00DBEEF);
    CHECK(g_iommu[1] == 0xBADC0FFE);

    iommu.write_64(0, 0);
    CHECK(g_iommu[0] == 0);
    CHECK(g_iommu[1] == 0);
}

TEST_CASE("phys_iommu: write_64_preserved")
{
    auto iommu = ::intel_x64::vtd::phys_iommu(g_iommu_base);

    g_iommu[0] = 0xFFFFFFFF;
    g_iommu[1] = 0xFFFFFFFF;
    iommu.write_64_preserved(0, 0, 0x00FF00FFFF00FF00);
    CHECK(g_iommu[0] == 0xFF00FF00);
    CHECK(g_iommu[1] == 0x00FF00FF);
}
