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

#include <catch/catch.hpp>

#include <bfstring.h>
#include <bferrorcodes.h>

TEST_CASE("ec_to_str: known")
{
    CHECK(ec_to_str(SUCCESS) == "SUCCESS"_s);
    CHECK(ec_to_str(ENTRY_ERROR_STACK_OVERFLOW) == "ENTRY_ERROR_STACK_OVERFLOW"_s);
    CHECK(ec_to_str(ENTRY_ERROR_VMM_INIT_FAILED) == "ENTRY_ERROR_VMM_INIT_FAILED"_s);
    CHECK(ec_to_str(ENTRY_ERROR_VMM_START_FAILED) == "ENTRY_ERROR_VMM_START_FAILED"_s);
    CHECK(ec_to_str(ENTRY_ERROR_VMM_STOP_FAILED) == "ENTRY_ERROR_VMM_STOP_FAILED"_s);
    CHECK(ec_to_str(ENTRY_ERROR_UNKNOWN) == "ENTRY_ERROR_UNKNOWN"_s);
    CHECK(ec_to_str(CRT_FAILURE) == "CRT_FAILURE"_s);
    CHECK(ec_to_str(REGISTER_EH_FRAME_FAILURE) == "REGISTER_EH_FRAME_FAILURE"_s);
    CHECK(ec_to_str(GET_DRR_FAILURE) == "GET_DRR_FAILURE"_s);
    CHECK(ec_to_str(MEMORY_MANAGER_FAILURE) == "MEMORY_MANAGER_FAILURE"_s);
    CHECK(ec_to_str(BFELF_ERROR_INVALID_ARG) == "BFELF_ERROR_INVALID_ARG"_s);
    CHECK(ec_to_str(BFELF_ERROR_INVALID_FILE) == "BFELF_ERROR_INVALID_FILE"_s);
    CHECK(ec_to_str(BFELF_ERROR_INVALID_INDEX) == "BFELF_ERROR_INVALID_INDEX"_s);
    CHECK(ec_to_str(BFELF_ERROR_INVALID_SIGNATURE) == "BFELF_ERROR_INVALID_SIGNATURE"_s);
    CHECK(ec_to_str(BFELF_ERROR_UNSUPPORTED_FILE) == "BFELF_ERROR_UNSUPPORTED_FILE"_s);
    CHECK(ec_to_str(BFELF_ERROR_INVALID_SEGMENT) == "BFELF_ERROR_INVALID_SEGMENT"_s);
    CHECK(ec_to_str(BFELF_ERROR_INVALID_SECTION) == "BFELF_ERROR_INVALID_SECTION"_s);
    CHECK(ec_to_str(BFELF_ERROR_LOADER_FULL) == "BFELF_ERROR_LOADER_FULL"_s);
    CHECK(ec_to_str(BFELF_ERROR_NO_SUCH_SYMBOL) == "BFELF_ERROR_NO_SUCH_SYMBOL"_s);
    CHECK(ec_to_str(BFELF_ERROR_MISMATCH) == "BFELF_ERROR_MISMATCH"_s);
    CHECK(ec_to_str(BFELF_ERROR_UNSUPPORTED_RELA) == "BFELF_ERROR_UNSUPPORTED_RELA"_s);
    CHECK(ec_to_str(BFELF_ERROR_OUT_OF_ORDER) == "BFELF_ERROR_OUT_OF_ORDER"_s);
    CHECK(ec_to_str(BFELF_ERROR_OUT_OF_MEMORY) == "BFELF_ERROR_OUT_OF_MEMORY"_s);
    CHECK(ec_to_str(BF_ERROR_INVALID_ARG) == "BF_ERROR_INVALID_ARG"_s);
    CHECK(ec_to_str(BF_ERROR_INVALID_INDEX) == "BF_ERROR_INVALID_INDEX"_s);
    CHECK(ec_to_str(BF_ERROR_NO_MODULES_ADDED) == "BF_ERROR_NO_MODULES_ADDED"_s);
    CHECK(ec_to_str(BF_ERROR_MAX_MODULES_REACHED) == "BF_ERROR_MAX_MODULES_REACHED"_s);
    CHECK(ec_to_str(BF_ERROR_VMM_INVALID_STATE) == "BF_ERROR_VMM_INVALID_STATE"_s);
    CHECK(ec_to_str(BF_ERROR_FAILED_TO_ADD_FILE) == "BF_ERROR_FAILED_TO_ADD_FILE"_s);
    CHECK(ec_to_str(BF_ERROR_FAILED_TO_DUMP_DR) == "BF_ERROR_FAILED_TO_DUMP_DR"_s);
    CHECK(ec_to_str(BF_ERROR_OUT_OF_MEMORY) == "BF_ERROR_OUT_OF_MEMORY"_s);
    CHECK(ec_to_str(BF_ERROR_VMM_CORRUPTED) == "BF_ERROR_VMM_CORRUPTED"_s);
    CHECK(ec_to_str(BF_ERROR_UNKNOWN) == "BF_ERROR_UNKNOWN"_s);
    CHECK(ec_to_str(BF_BAD_ALLOC) == "BF_BAD_ALLOC"_s);
    CHECK(ec_to_str(BF_IOCTL_FAILURE) == "BF_IOCTL_FAILURE"_s);
}

TEST_CASE("ec_to_str: unknown")
{
    CHECK(ec_to_str(0x123456789) == "UNDEFINED_ERROR_CODE"_s);
}
