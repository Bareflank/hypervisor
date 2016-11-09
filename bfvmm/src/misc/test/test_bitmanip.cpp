//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#include <test.h>
#include <bitmanip.h>

void
misc_ut::test_bitmanip_set_bit()
{
    this->expect_true(set_bit(0x00000000U, 0) == 0x00000001U);
    this->expect_true(set_bit(0x00000000U, 8) == 0x00000100U);
}

void
misc_ut::test_bitmanip_clear_bit()
{
    this->expect_true(clear_bit(0xFFFFFFFFU, 0) == 0xFFFFFFFEU);
    this->expect_true(clear_bit(0xFFFFFFFFU, 8) == 0xFFFFFEFFU);
}

void
misc_ut::test_bitmanip_get_bit()
{
    this->expect_true(get_bit(0xFFFFFFFFU, 0) == 1);
    this->expect_true(get_bit(0x00000000U, 0) == 0);
    this->expect_true(get_bit(0xFFFFFFFFU, 8) == 1);
    this->expect_true(get_bit(0x00000000U, 8) == 0);
}

void
misc_ut::test_bitmanip_is_bit_set()
{
    this->expect_true(is_bit_set(0xFFFFFFFFU, 0) == true);
    this->expect_true(is_bit_set(0x00000000U, 0) == false);
    this->expect_true(is_bit_set(0xFFFFFFFFU, 8) == true);
    this->expect_true(is_bit_set(0x00000000U, 8) == false);
}

void
misc_ut::test_bitmanip_is_bit_cleared()
{
    this->expect_true(is_bit_cleared(0xFFFFFFFFU, 0) == false);
    this->expect_true(is_bit_cleared(0x00000000U, 0) == true);
    this->expect_true(is_bit_cleared(0xFFFFFFFFU, 8) == false);
    this->expect_true(is_bit_cleared(0x00000000U, 8) == true);
}

void
misc_ut::test_bitmanip_num_bits_set()
{
    this->expect_true(num_bits_set(0xFFFFFFFFU) == 32);
    this->expect_true(num_bits_set(0x00000000U) == 0);
}

void
misc_ut::test_bitmanip_get_bits()
{
    this->expect_true(get_bits(0xFFFFFFFFU, 0x11111111U) == 0x11111111U);
    this->expect_true(get_bits(0x00000000U, 0x11111111U) == 0x00000000U);
    this->expect_true(get_bits(0x88888888U, 0x11111111U) == 0x00000000U);
    this->expect_true(get_bits(0xF0F0F0F0U, 0x11111111U) == 0x10101010U);
}

void
misc_ut::test_bitmanip_set_bits()
{
    this->expect_true(set_bits(0xFFFFFFFFU, 0x00111100U, 0x00000000U) == 0xFFEEEEFFU);
    this->expect_true(set_bits(0x00000000U, 0x00111100U, 0xFFFFFFFFU) == 0x00111100U);
    this->expect_true(set_bits(0x88888888U, 0x00111100U, 0x00111100U) == 0x88999988U);
    this->expect_true(set_bits(0xF0F0F0F0U, 0x00111100U, 0x00111100U) == 0xF0F1F1F0U);
}
