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

#include "../../include/alloc_and_copy_mk_elf_segments.h"
#include "../../include/free_mk_elf_segments.h"

#include <bfelf/bfelf_elf64_ehdr_t.h>
#include <bfelf/bfelf_elf64_phdr_t.h>
#include <constants.h>
#include <elf_file_t.h>
#include <elf_segment_t.h>
#include <helpers.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace loader
{
    /// <!-- description -->
    ///   @brief Used to execute the actual checks. We put the checks in this
    ///     function so that we can validate the tests both at compile-time
    ///     and at run-time. If a bsl::ut_check fails, the tests will either
    ///     fail fast at run-time, or will produce a compile-time error.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Always returns bsl::exit_success.
    ///
    [[nodiscard]] constexpr auto
    tests() noexcept -> bsl::exit_code
    {
        helpers::init();
        constexpr auto func{&alloc_and_copy_mk_elf_segments};

        bsl::ut_scenario{"success"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                elf_file_t mut_file{};
                bsl::array<elf_segment_t, HYPERVISOR_MAX_SEGMENTS> mut_segments{};
                bfelf_elf64_ehdr_t mut_ehdr{};
                constexpr auto num_segments{42_umx};
                bsl::array<bfelf_elf64_phdr_t, num_segments.get()> mut_phdrtbl{};
                constexpr auto buf_size{0x2042_umx};
                bsl::array<bsl::uint8, buf_size.get()> mut_buf{};
                constexpr auto p_memsz{0x3023_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_file.addr = &mut_ehdr;
                    mut_file.size = sizeof(bfelf_elf64_ehdr_t);
                    mut_ehdr.e_ident[bfelf_ei_mag0] = bfelf_elfmag0;
                    mut_ehdr.e_ident[bfelf_ei_mag1] = bfelf_elfmag1;
                    mut_ehdr.e_ident[bfelf_ei_mag2] = bfelf_elfmag2;
                    mut_ehdr.e_ident[bfelf_ei_mag3] = bfelf_elfmag3;
                    mut_ehdr.e_ident[bfelf_ei_class] = bfelf_elfclass64;
                    mut_ehdr.e_ident[bfelf_ei_osabi] = bfelf_elfosabi_sysv;
                    mut_ehdr.e_type = bfelf_et_exec;
                    mut_ehdr.e_phdr = mut_phdrtbl.data();
                    mut_ehdr.e_phnum = bsl::to_u16(num_segments).get();
                    mut_phdrtbl.front().p_type = bfelf_pt_load;
                    mut_phdrtbl.front().p_offset = mut_buf.data();
                    mut_phdrtbl.front().p_filesz = mut_buf.size().get();
                    mut_phdrtbl.front().p_memsz = p_memsz.get();
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_check(func(&mut_file, mut_segments.data()));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_elf_segments(mut_segments.data());
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"validate_elf64_ehdr bfelf_ei_mag0 fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                elf_file_t mut_file{};
                bsl::array<elf_segment_t, HYPERVISOR_MAX_SEGMENTS> mut_segments{};
                bfelf_elf64_ehdr_t mut_ehdr{};
                constexpr auto num_segments{42_umx};
                bsl::array<bfelf_elf64_phdr_t, num_segments.get()> mut_phdrtbl{};
                constexpr auto buf_size{0x2042_umx};
                bsl::array<bsl::uint8, buf_size.get()> mut_buf{};
                constexpr auto p_memsz{0x3023_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_file.addr = &mut_ehdr;
                    mut_file.size = sizeof(bfelf_elf64_ehdr_t);
                    mut_ehdr.e_ident[bfelf_ei_mag1] = bfelf_elfmag1;
                    mut_ehdr.e_ident[bfelf_ei_mag2] = bfelf_elfmag2;
                    mut_ehdr.e_ident[bfelf_ei_mag3] = bfelf_elfmag3;
                    mut_ehdr.e_ident[bfelf_ei_class] = bfelf_elfclass64;
                    mut_ehdr.e_ident[bfelf_ei_osabi] = bfelf_elfosabi_sysv;
                    mut_ehdr.e_type = bfelf_et_exec;
                    mut_ehdr.e_phdr = mut_phdrtbl.data();
                    mut_ehdr.e_phnum = bsl::to_u16(num_segments).get();
                    mut_phdrtbl.front().p_type = bfelf_pt_load;
                    mut_phdrtbl.front().p_offset = mut_buf.data();
                    mut_phdrtbl.front().p_filesz = mut_buf.size().get();
                    mut_phdrtbl.front().p_memsz = p_memsz.get();
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(&mut_file, mut_segments.data()));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"validate_elf64_ehdr bfelf_ei_mag1 fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                elf_file_t mut_file{};
                bsl::array<elf_segment_t, HYPERVISOR_MAX_SEGMENTS> mut_segments{};
                bfelf_elf64_ehdr_t mut_ehdr{};
                constexpr auto num_segments{42_umx};
                bsl::array<bfelf_elf64_phdr_t, num_segments.get()> mut_phdrtbl{};
                constexpr auto buf_size{0x2042_umx};
                bsl::array<bsl::uint8, buf_size.get()> mut_buf{};
                constexpr auto p_memsz{0x3023_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_file.addr = &mut_ehdr;
                    mut_file.size = sizeof(bfelf_elf64_ehdr_t);
                    mut_ehdr.e_ident[bfelf_ei_mag0] = bfelf_elfmag0;
                    mut_ehdr.e_ident[bfelf_ei_mag2] = bfelf_elfmag2;
                    mut_ehdr.e_ident[bfelf_ei_mag3] = bfelf_elfmag3;
                    mut_ehdr.e_ident[bfelf_ei_class] = bfelf_elfclass64;
                    mut_ehdr.e_ident[bfelf_ei_osabi] = bfelf_elfosabi_sysv;
                    mut_ehdr.e_type = bfelf_et_exec;
                    mut_ehdr.e_phdr = mut_phdrtbl.data();
                    mut_ehdr.e_phnum = bsl::to_u16(num_segments).get();
                    mut_phdrtbl.front().p_type = bfelf_pt_load;
                    mut_phdrtbl.front().p_offset = mut_buf.data();
                    mut_phdrtbl.front().p_filesz = mut_buf.size().get();
                    mut_phdrtbl.front().p_memsz = p_memsz.get();
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(&mut_file, mut_segments.data()));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"validate_elf64_ehdr bfelf_ei_mag2 fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                elf_file_t mut_file{};
                bsl::array<elf_segment_t, HYPERVISOR_MAX_SEGMENTS> mut_segments{};
                bfelf_elf64_ehdr_t mut_ehdr{};
                constexpr auto num_segments{42_umx};
                bsl::array<bfelf_elf64_phdr_t, num_segments.get()> mut_phdrtbl{};
                constexpr auto buf_size{0x2042_umx};
                bsl::array<bsl::uint8, buf_size.get()> mut_buf{};
                constexpr auto p_memsz{0x3023_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_file.addr = &mut_ehdr;
                    mut_file.size = sizeof(bfelf_elf64_ehdr_t);
                    mut_ehdr.e_ident[bfelf_ei_mag0] = bfelf_elfmag0;
                    mut_ehdr.e_ident[bfelf_ei_mag1] = bfelf_elfmag1;
                    mut_ehdr.e_ident[bfelf_ei_mag3] = bfelf_elfmag3;
                    mut_ehdr.e_ident[bfelf_ei_class] = bfelf_elfclass64;
                    mut_ehdr.e_ident[bfelf_ei_osabi] = bfelf_elfosabi_sysv;
                    mut_ehdr.e_type = bfelf_et_exec;
                    mut_ehdr.e_phdr = mut_phdrtbl.data();
                    mut_ehdr.e_phnum = bsl::to_u16(num_segments).get();
                    mut_phdrtbl.front().p_type = bfelf_pt_load;
                    mut_phdrtbl.front().p_offset = mut_buf.data();
                    mut_phdrtbl.front().p_filesz = mut_buf.size().get();
                    mut_phdrtbl.front().p_memsz = p_memsz.get();
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(&mut_file, mut_segments.data()));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"validate_elf64_ehdr bfelf_ei_mag3 fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                elf_file_t mut_file{};
                bsl::array<elf_segment_t, HYPERVISOR_MAX_SEGMENTS> mut_segments{};
                bfelf_elf64_ehdr_t mut_ehdr{};
                constexpr auto num_segments{42_umx};
                bsl::array<bfelf_elf64_phdr_t, num_segments.get()> mut_phdrtbl{};
                constexpr auto buf_size{0x2042_umx};
                bsl::array<bsl::uint8, buf_size.get()> mut_buf{};
                constexpr auto p_memsz{0x3023_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_file.addr = &mut_ehdr;
                    mut_file.size = sizeof(bfelf_elf64_ehdr_t);
                    mut_ehdr.e_ident[bfelf_ei_mag0] = bfelf_elfmag0;
                    mut_ehdr.e_ident[bfelf_ei_mag1] = bfelf_elfmag1;
                    mut_ehdr.e_ident[bfelf_ei_mag2] = bfelf_elfmag2;
                    mut_ehdr.e_ident[bfelf_ei_class] = bfelf_elfclass64;
                    mut_ehdr.e_ident[bfelf_ei_osabi] = bfelf_elfosabi_sysv;
                    mut_ehdr.e_type = bfelf_et_exec;
                    mut_ehdr.e_phdr = mut_phdrtbl.data();
                    mut_ehdr.e_phnum = bsl::to_u16(num_segments).get();
                    mut_phdrtbl.front().p_type = bfelf_pt_load;
                    mut_phdrtbl.front().p_offset = mut_buf.data();
                    mut_phdrtbl.front().p_filesz = mut_buf.size().get();
                    mut_phdrtbl.front().p_memsz = p_memsz.get();
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(&mut_file, mut_segments.data()));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"validate_elf64_ehdr bfelf_ei_class fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                elf_file_t mut_file{};
                bsl::array<elf_segment_t, HYPERVISOR_MAX_SEGMENTS> mut_segments{};
                bfelf_elf64_ehdr_t mut_ehdr{};
                constexpr auto num_segments{42_umx};
                bsl::array<bfelf_elf64_phdr_t, num_segments.get()> mut_phdrtbl{};
                constexpr auto buf_size{0x2042_umx};
                bsl::array<bsl::uint8, buf_size.get()> mut_buf{};
                constexpr auto p_memsz{0x3023_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_file.addr = &mut_ehdr;
                    mut_file.size = sizeof(bfelf_elf64_ehdr_t);
                    mut_ehdr.e_ident[bfelf_ei_mag0] = bfelf_elfmag0;
                    mut_ehdr.e_ident[bfelf_ei_mag1] = bfelf_elfmag1;
                    mut_ehdr.e_ident[bfelf_ei_mag2] = bfelf_elfmag2;
                    mut_ehdr.e_ident[bfelf_ei_mag3] = bfelf_elfmag3;
                    mut_ehdr.e_ident[bfelf_ei_osabi] = bfelf_elfosabi_sysv;
                    mut_ehdr.e_type = bfelf_et_exec;
                    mut_ehdr.e_phdr = mut_phdrtbl.data();
                    mut_ehdr.e_phnum = bsl::to_u16(num_segments).get();
                    mut_phdrtbl.front().p_type = bfelf_pt_load;
                    mut_phdrtbl.front().p_offset = mut_buf.data();
                    mut_phdrtbl.front().p_filesz = mut_buf.size().get();
                    mut_phdrtbl.front().p_memsz = p_memsz.get();
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(&mut_file, mut_segments.data()));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"validate_elf64_ehdr bfelf_ei_osabi fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                elf_file_t mut_file{};
                bsl::array<elf_segment_t, HYPERVISOR_MAX_SEGMENTS> mut_segments{};
                bfelf_elf64_ehdr_t mut_ehdr{};
                constexpr auto num_segments{42_umx};
                bsl::array<bfelf_elf64_phdr_t, num_segments.get()> mut_phdrtbl{};
                constexpr auto buf_size{0x2042_umx};
                bsl::array<bsl::uint8, buf_size.get()> mut_buf{};
                constexpr auto p_memsz{0x3023_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_file.addr = &mut_ehdr;
                    mut_file.size = sizeof(bfelf_elf64_ehdr_t);
                    mut_ehdr.e_ident[bfelf_ei_mag0] = bfelf_elfmag0;
                    mut_ehdr.e_ident[bfelf_ei_mag1] = bfelf_elfmag1;
                    mut_ehdr.e_ident[bfelf_ei_mag2] = bfelf_elfmag2;
                    mut_ehdr.e_ident[bfelf_ei_mag3] = bfelf_elfmag3;
                    mut_ehdr.e_ident[bfelf_ei_class] = bfelf_elfclass64;
                    mut_ehdr.e_ident[bfelf_ei_osabi] = bfelf_elfosabi_hpux;
                    mut_ehdr.e_type = bfelf_et_exec;
                    mut_ehdr.e_phdr = mut_phdrtbl.data();
                    mut_ehdr.e_phnum = bsl::to_u16(num_segments).get();
                    mut_phdrtbl.front().p_type = bfelf_pt_load;
                    mut_phdrtbl.front().p_offset = mut_buf.data();
                    mut_phdrtbl.front().p_filesz = mut_buf.size().get();
                    mut_phdrtbl.front().p_memsz = p_memsz.get();
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(&mut_file, mut_segments.data()));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"validate_elf64_ehdr e_type fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                elf_file_t mut_file{};
                bsl::array<elf_segment_t, HYPERVISOR_MAX_SEGMENTS> mut_segments{};
                bfelf_elf64_ehdr_t mut_ehdr{};
                constexpr auto num_segments{42_umx};
                bsl::array<bfelf_elf64_phdr_t, num_segments.get()> mut_phdrtbl{};
                constexpr auto buf_size{0x2042_umx};
                bsl::array<bsl::uint8, buf_size.get()> mut_buf{};
                constexpr auto p_memsz{0x3023_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_file.addr = &mut_ehdr;
                    mut_file.size = sizeof(bfelf_elf64_ehdr_t);
                    mut_ehdr.e_ident[bfelf_ei_mag0] = bfelf_elfmag0;
                    mut_ehdr.e_ident[bfelf_ei_mag1] = bfelf_elfmag1;
                    mut_ehdr.e_ident[bfelf_ei_mag2] = bfelf_elfmag2;
                    mut_ehdr.e_ident[bfelf_ei_mag3] = bfelf_elfmag3;
                    mut_ehdr.e_ident[bfelf_ei_class] = bfelf_elfclass64;
                    mut_ehdr.e_ident[bfelf_ei_osabi] = bfelf_elfosabi_sysv;
                    mut_ehdr.e_phdr = mut_phdrtbl.data();
                    mut_ehdr.e_phnum = bsl::to_u16(num_segments).get();
                    mut_phdrtbl.front().p_type = bfelf_pt_load;
                    mut_phdrtbl.front().p_offset = mut_buf.data();
                    mut_phdrtbl.front().p_filesz = mut_buf.size().get();
                    mut_phdrtbl.front().p_memsz = p_memsz.get();
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(&mut_file, mut_segments.data()));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"no pt_load segments"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                elf_file_t mut_file{};
                bsl::array<elf_segment_t, HYPERVISOR_MAX_SEGMENTS> mut_segments{};
                bfelf_elf64_ehdr_t mut_ehdr{};
                bfelf_elf64_phdr_t mut_phdr{};
                constexpr auto e_phnum{1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_file.addr = &mut_ehdr;
                    mut_file.size = sizeof(bfelf_elf64_ehdr_t);
                    mut_ehdr.e_ident[bfelf_ei_mag0] = bfelf_elfmag0;
                    mut_ehdr.e_ident[bfelf_ei_mag1] = bfelf_elfmag1;
                    mut_ehdr.e_ident[bfelf_ei_mag2] = bfelf_elfmag2;
                    mut_ehdr.e_ident[bfelf_ei_mag3] = bfelf_elfmag3;
                    mut_ehdr.e_ident[bfelf_ei_class] = bfelf_elfclass64;
                    mut_ehdr.e_ident[bfelf_ei_osabi] = bfelf_elfosabi_sysv;
                    mut_ehdr.e_type = bfelf_et_exec;
                    mut_ehdr.e_phdr = &mut_phdr;
                    mut_ehdr.e_phnum = e_phnum.get();
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_check(func(&mut_file, mut_segments.data()));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"too many segments"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                elf_file_t mut_file{};
                bsl::array<elf_segment_t, HYPERVISOR_MAX_SEGMENTS> mut_segments{};
                bfelf_elf64_ehdr_t mut_ehdr{};
                constexpr auto num_segments{42_umx};
                bsl::array<bfelf_elf64_phdr_t, num_segments.get()> mut_phdrtbl{};
                constexpr auto buf_size{0x2042_umx};
                bsl::array<bsl::uint8, buf_size.get()> mut_buf{};
                constexpr auto p_memsz{0x3023_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_file.addr = &mut_ehdr;
                    mut_file.size = sizeof(bfelf_elf64_ehdr_t);
                    mut_ehdr.e_ident[bfelf_ei_mag0] = bfelf_elfmag0;
                    mut_ehdr.e_ident[bfelf_ei_mag1] = bfelf_elfmag1;
                    mut_ehdr.e_ident[bfelf_ei_mag2] = bfelf_elfmag2;
                    mut_ehdr.e_ident[bfelf_ei_mag3] = bfelf_elfmag3;
                    mut_ehdr.e_ident[bfelf_ei_class] = bfelf_elfclass64;
                    mut_ehdr.e_ident[bfelf_ei_osabi] = bfelf_elfosabi_sysv;
                    mut_ehdr.e_type = bfelf_et_exec;
                    mut_ehdr.e_phdr = mut_phdrtbl.data();
                    mut_ehdr.e_phnum = bsl::to_u16(num_segments).get();
                    for (auto &mut_phdr : mut_phdrtbl) {
                        mut_phdr.p_type = bfelf_pt_load;
                        mut_phdr.p_offset = mut_buf.data();
                        mut_phdr.p_filesz = mut_buf.size().get();
                        mut_phdr.p_memsz = p_memsz.get();
                    }
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(&mut_file, mut_segments.data()));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"success"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                elf_file_t mut_file{};
                bsl::array<elf_segment_t, HYPERVISOR_MAX_SEGMENTS> mut_segments{};
                bfelf_elf64_ehdr_t mut_ehdr{};
                constexpr auto num_segments{42_umx};
                bsl::array<bfelf_elf64_phdr_t, num_segments.get()> mut_phdrtbl{};
                constexpr auto buf_size{0x2042_umx};
                bsl::array<bsl::uint8, buf_size.get()> mut_buf{};
                constexpr auto p_memsz{0x3023_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_file.addr = &mut_ehdr;
                    mut_file.size = sizeof(bfelf_elf64_ehdr_t);
                    mut_ehdr.e_ident[bfelf_ei_mag0] = bfelf_elfmag0;
                    mut_ehdr.e_ident[bfelf_ei_mag1] = bfelf_elfmag1;
                    mut_ehdr.e_ident[bfelf_ei_mag2] = bfelf_elfmag2;
                    mut_ehdr.e_ident[bfelf_ei_mag3] = bfelf_elfmag3;
                    mut_ehdr.e_ident[bfelf_ei_class] = bfelf_elfclass64;
                    mut_ehdr.e_ident[bfelf_ei_osabi] = bfelf_elfosabi_sysv;
                    mut_ehdr.e_type = bfelf_et_exec;
                    mut_ehdr.e_phdr = mut_phdrtbl.data();
                    mut_ehdr.e_phnum = bsl::to_u16(num_segments).get();
                    mut_phdrtbl.front().p_type = bfelf_pt_load;
                    mut_phdrtbl.front().p_offset = mut_buf.data();
                    mut_phdrtbl.front().p_filesz = mut_buf.size().get();
                    mut_phdrtbl.front().p_memsz = p_memsz.get();
                    helpers::g_mut_platform_alloc = 1;
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(&mut_file, mut_segments.data()));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::reset();
                    };
                };
            };
        };

        return helpers::fini();
    }
}

/// <!-- description -->
///   @brief Main function for this unit test. If a call to bsl::ut_check() fails
///     the application will fast fail. If all calls to bsl::ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
[[nodiscard]] auto
main() noexcept -> bsl::exit_code
{
    bsl::enable_color();
    return loader::tests();
}
