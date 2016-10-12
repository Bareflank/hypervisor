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
#include <error_codes.h>

#define STRINGIFY_MACRO(a) std::string(#a)

void
misc_ut::test_error_codes_valid()
{
    this->expect_true(ec_to_str(SUCCESS) == STRINGIFY_MACRO(SUCCESS));

    this->expect_true(ec_to_str(ENTRY_ERROR_STACK_OVERFLOW) == STRINGIFY_MACRO(ENTRY_ERROR_STACK_OVERFLOW));
    this->expect_true(ec_to_str(ENTRY_ERROR_VMM_INIT_FAILED) == STRINGIFY_MACRO(ENTRY_ERROR_VMM_INIT_FAILED));
    this->expect_true(ec_to_str(ENTRY_ERROR_VMM_START_FAILED) == STRINGIFY_MACRO(ENTRY_ERROR_VMM_START_FAILED));
    this->expect_true(ec_to_str(ENTRY_ERROR_VMM_STOP_FAILED) == STRINGIFY_MACRO(ENTRY_ERROR_VMM_STOP_FAILED));
    this->expect_true(ec_to_str(ENTRY_ERROR_UNKNOWN) == STRINGIFY_MACRO(ENTRY_ERROR_UNKNOWN));

    this->expect_true(ec_to_str(CRT_FAILURE) == STRINGIFY_MACRO(CRT_FAILURE));

    this->expect_true(ec_to_str(REGISTER_EH_FRAME_FAILURE) == STRINGIFY_MACRO(REGISTER_EH_FRAME_FAILURE));

    this->expect_true(ec_to_str(GET_DRR_FAILURE) == STRINGIFY_MACRO(GET_DRR_FAILURE));

    this->expect_true(ec_to_str(MEMORY_MANAGER_FAILURE) == STRINGIFY_MACRO(MEMORY_MANAGER_FAILURE));

    this->expect_true(ec_to_str(BFELF_ERROR_INVALID_ARG) == STRINGIFY_MACRO(BFELF_ERROR_INVALID_ARG));
    this->expect_true(ec_to_str(BFELF_ERROR_INVALID_FILE) == STRINGIFY_MACRO(BFELF_ERROR_INVALID_FILE));
    this->expect_true(ec_to_str(BFELF_ERROR_INVALID_INDEX) == STRINGIFY_MACRO(BFELF_ERROR_INVALID_INDEX));
    this->expect_true(ec_to_str(BFELF_ERROR_INVALID_STRING) == STRINGIFY_MACRO(BFELF_ERROR_INVALID_STRING));
    this->expect_true(ec_to_str(BFELF_ERROR_INVALID_SIGNATURE) == STRINGIFY_MACRO(BFELF_ERROR_INVALID_SIGNATURE));
    this->expect_true(ec_to_str(BFELF_ERROR_UNSUPPORTED_FILE) == STRINGIFY_MACRO(BFELF_ERROR_UNSUPPORTED_FILE));
    this->expect_true(ec_to_str(BFELF_ERROR_INVALID_SEGMENT) == STRINGIFY_MACRO(BFELF_ERROR_INVALID_SEGMENT));
    this->expect_true(ec_to_str(BFELF_ERROR_INVALID_SECTION) == STRINGIFY_MACRO(BFELF_ERROR_INVALID_SECTION));
    this->expect_true(ec_to_str(BFELF_ERROR_LOADER_FULL) == STRINGIFY_MACRO(BFELF_ERROR_LOADER_FULL));
    this->expect_true(ec_to_str(BFELF_ERROR_NO_SUCH_SYMBOL) == STRINGIFY_MACRO(BFELF_ERROR_NO_SUCH_SYMBOL));
    this->expect_true(ec_to_str(BFELF_ERROR_MISMATCH) == STRINGIFY_MACRO(BFELF_ERROR_MISMATCH));
    this->expect_true(ec_to_str(BFELF_ERROR_UNSUPPORTED_RELA) == STRINGIFY_MACRO(BFELF_ERROR_UNSUPPORTED_RELA));
    this->expect_true(ec_to_str(BFELF_ERROR_OUT_OF_ORDER) == STRINGIFY_MACRO(BFELF_ERROR_OUT_OF_ORDER));

    this->expect_true(ec_to_str(BF_ERROR_INVALID_ARG) == STRINGIFY_MACRO(BF_ERROR_INVALID_ARG));
    this->expect_true(ec_to_str(BF_ERROR_INVALID_INDEX) == STRINGIFY_MACRO(BF_ERROR_INVALID_INDEX));
    this->expect_true(ec_to_str(BF_ERROR_NO_MODULES_ADDED) == STRINGIFY_MACRO(BF_ERROR_NO_MODULES_ADDED));
    this->expect_true(ec_to_str(BF_ERROR_MAX_MODULES_REACHED) == STRINGIFY_MACRO(BF_ERROR_MAX_MODULES_REACHED));
    this->expect_true(ec_to_str(BF_ERROR_VMM_INVALID_STATE) == STRINGIFY_MACRO(BF_ERROR_VMM_INVALID_STATE));
    this->expect_true(ec_to_str(BF_ERROR_FAILED_TO_ADD_FILE) == STRINGIFY_MACRO(BF_ERROR_FAILED_TO_ADD_FILE));
    this->expect_true(ec_to_str(BF_ERROR_FAILED_TO_DUMP_DR) == STRINGIFY_MACRO(BF_ERROR_FAILED_TO_DUMP_DR));
    this->expect_true(ec_to_str(BF_ERROR_OUT_OF_MEMORY) == STRINGIFY_MACRO(BF_ERROR_OUT_OF_MEMORY));
    this->expect_true(ec_to_str(BF_ERROR_VMM_CORRUPTED) == STRINGIFY_MACRO(BF_ERROR_VMM_CORRUPTED));
    this->expect_true(ec_to_str(BF_ERROR_UNKNOWN) == STRINGIFY_MACRO(BF_ERROR_UNKNOWN));

    this->expect_true(ec_to_str(BF_BAD_ALLOC) == STRINGIFY_MACRO(BF_BAD_ALLOC));

    this->expect_true(ec_to_str(BF_IOCTL_FAILURE) == STRINGIFY_MACRO(BF_IOCTL_FAILURE));
}

void
misc_ut::test_error_codes_unknown()
{
    this->expect_true(ec_to_str(0x123456789) == std::string("UNDEFINED_ERROR_CODE"));
}
