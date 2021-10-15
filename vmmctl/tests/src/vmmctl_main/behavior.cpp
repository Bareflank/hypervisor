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

#include "../../../src/vmmctl_main.hpp"

#include <debug_ring_t.hpp>
#include <dump_vmm_args_t.hpp>
#include <ioctl_t.hpp>
#include <loader_platform_interface.hpp>

#include <bsl/arguments.hpp>
#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace mk
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
        bsl::ut_scenario{"help"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmmctl::vmmctl_main mut_vmmctl{};
                vmmctl::ioctl_t mut_ioctl{};
                bsl::array const argv{"-h"};
                bsl::arguments mut_args{bsl::to_umx(argv.size()), argv.data()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_vmmctl.process(mut_args, mut_ioctl));
                };
            };

            bsl::ut_given{} = []() noexcept {
                vmmctl::vmmctl_main mut_vmmctl{};
                vmmctl::ioctl_t mut_ioctl{};
                bsl::array const argv{"--help"};
                bsl::arguments mut_args{bsl::to_umx(argv.size()), argv.data()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_vmmctl.process(mut_args, mut_ioctl));
                };
            };
        };

        bsl::ut_scenario{"missing command"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmmctl::vmmctl_main mut_vmmctl{};
                vmmctl::ioctl_t mut_ioctl{"success"};
                bsl::array const argv{"start", "kernel", "extension1", "extension2"};
                bsl::arguments mut_args{{}, argv.data()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_vmmctl.process(mut_args, mut_ioctl));
                };
            };
        };

        bsl::ut_scenario{"invalid command"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmmctl::vmmctl_main mut_vmmctl{};
                vmmctl::ioctl_t mut_ioctl{"success"};
                bsl::array const argv{"kar en tuk", "kernel", "extension1", "extension2"};
                bsl::arguments mut_args{bsl::to_umx(argv.size()), argv.data()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_vmmctl.process(mut_args, mut_ioctl));
                };
            };
        };

        bsl::ut_scenario{"start"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                vmmctl::vmmctl_main mut_vmmctl{};
                vmmctl::ioctl_t mut_ioctl{"success"};
                bsl::array const argv{"start", "kernel", "extension1", "extension2"};
                bsl::arguments mut_args{bsl::to_umx(argv.size()), argv.data()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_vmmctl.process(mut_args, mut_ioctl));
                };
            };
        };

        bsl::ut_scenario{"start too many extensions"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmmctl::vmmctl_main mut_vmmctl{};
                vmmctl::ioctl_t mut_ioctl{"success"};
                bsl::array const argv{"start", "kernel", "extension1", "extension2", "extension3"};
                bsl::arguments mut_args{bsl::to_umx(argv.size()), argv.data()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_vmmctl.process(mut_args, mut_ioctl));
                };
            };
        };

        bsl::ut_scenario{"start empty kernel path"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmmctl::vmmctl_main mut_vmmctl{};
                vmmctl::ioctl_t mut_ioctl{"success"};
                bsl::array const argv{"start", "", "extension"};
                bsl::arguments mut_args{bsl::to_umx(argv.size()), argv.data()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_vmmctl.process(mut_args, mut_ioctl));
                };
            };
        };

        bsl::ut_scenario{"start invalid kernel path"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmmctl::vmmctl_main mut_vmmctl{};
                vmmctl::ioctl_t mut_ioctl{"success"};
                bsl::array const argv{"start", "failure", "extension"};
                bsl::arguments mut_args{bsl::to_umx(argv.size()), argv.data()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_vmmctl.process(mut_args, mut_ioctl));
                };
            };
        };

        bsl::ut_scenario{"start empty extension path"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmmctl::vmmctl_main mut_vmmctl{};
                vmmctl::ioctl_t mut_ioctl{"success"};
                bsl::array const argv{"start", "kernel", ""};
                bsl::arguments mut_args{bsl::to_umx(argv.size()), argv.data()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_vmmctl.process(mut_args, mut_ioctl));
                };
            };
        };

        bsl::ut_scenario{"start invalid extension path"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmmctl::vmmctl_main mut_vmmctl{};
                vmmctl::ioctl_t mut_ioctl{"success"};
                bsl::array const argv{"start", "kernel", "failure"};
                bsl::arguments mut_args{bsl::to_umx(argv.size()), argv.data()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_vmmctl.process(mut_args, mut_ioctl));
                };
            };
        };

        bsl::ut_scenario{"start fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmmctl::vmmctl_main mut_vmmctl{};
                vmmctl::ioctl_t mut_ioctl{"failure"};
                bsl::array const argv{"start", "kernel", "extension"};
                bsl::arguments mut_args{bsl::to_umx(argv.size()), argv.data()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_vmmctl.process(mut_args, mut_ioctl));
                };
            };
        };

        bsl::ut_scenario{"stop"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmmctl::vmmctl_main mut_vmmctl{};
                vmmctl::ioctl_t mut_ioctl{"success"};
                bsl::array const argv{"stop"};
                bsl::arguments mut_args{bsl::to_umx(argv.size()), argv.data()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_vmmctl.process(mut_args, mut_ioctl));
                };
            };
        };

        bsl::ut_scenario{"stop fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmmctl::vmmctl_main mut_vmmctl{};
                vmmctl::ioctl_t mut_ioctl{"failure"};
                bsl::array const argv{"stop"};
                bsl::arguments mut_args{bsl::to_umx(argv.size()), argv.data()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_vmmctl.process(mut_args, mut_ioctl));
                };
            };
        };

        bsl::ut_scenario{"dump"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmmctl::vmmctl_main mut_vmmctl{};
                vmmctl::ioctl_t mut_ioctl{"success"};
                bsl::array const argv{"dump"};
                bsl::arguments mut_args{bsl::to_umx(argv.size()), argv.data()};
                loader::dump_vmm_args_t mut_dump_args{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ioctl.write(loader::DUMP_VMM, &mut_dump_args));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vmmctl.process(mut_args, mut_ioctl));
                    };
                };
            };
        };

        bsl::ut_scenario{"dump invalid epos"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmmctl::vmmctl_main mut_vmmctl{};
                vmmctl::ioctl_t mut_ioctl{"success"};
                bsl::array const argv{"dump"};
                bsl::arguments mut_args{bsl::to_umx(argv.size()), argv.data()};
                loader::dump_vmm_args_t mut_dump_args{};
                constexpr auto invalid{0xFFFFFFFFFFFFFFFF_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_dump_args.debug_ring.epos = invalid.get();
                    bsl::ut_required_step(mut_ioctl.write(loader::DUMP_VMM, &mut_dump_args));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vmmctl.process(mut_args, mut_ioctl));
                    };
                };
            };
        };

        bsl::ut_scenario{"dump invalid spos"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmmctl::vmmctl_main mut_vmmctl{};
                vmmctl::ioctl_t mut_ioctl{"success"};
                bsl::array const argv{"dump"};
                bsl::arguments mut_args{bsl::to_umx(argv.size()), argv.data()};
                loader::dump_vmm_args_t mut_dump_args{};
                constexpr auto invalid{0xFFFFFFFFFFFFFFFF_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_dump_args.debug_ring.spos = invalid.get();
                    bsl::ut_required_step(mut_ioctl.write(loader::DUMP_VMM, &mut_dump_args));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vmmctl.process(mut_args, mut_ioctl));
                    };
                };
            };
        };

        bsl::ut_scenario{"nothing to dump"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmmctl::vmmctl_main mut_vmmctl{};
                vmmctl::ioctl_t mut_ioctl{"success"};
                bsl::array const argv{"dump"};
                bsl::arguments mut_args{bsl::to_umx(argv.size()), argv.data()};
                loader::dump_vmm_args_t mut_dump_args{};
                constexpr auto epos{5_umx};
                constexpr auto spos{5_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_dump_args.debug_ring.epos = epos.get();
                    mut_dump_args.debug_ring.spos = spos.get();
                    bsl::ut_required_step(mut_ioctl.write(loader::DUMP_VMM, &mut_dump_args));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vmmctl.process(mut_args, mut_ioctl));
                    };
                };
            };
        };

        bsl::ut_scenario{"dump full"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmmctl::vmmctl_main mut_vmmctl{};
                vmmctl::ioctl_t mut_ioctl{"success"};
                bsl::array const argv{"dump"};
                bsl::arguments mut_args{bsl::to_umx(argv.size()), argv.data()};
                loader::dump_vmm_args_t mut_dump_args{};
                constexpr auto epos{4_umx};
                constexpr auto spos{5_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_dump_args.debug_ring.epos = epos.get();
                    mut_dump_args.debug_ring.spos = spos.get();
                    bsl::ut_required_step(mut_ioctl.write(loader::DUMP_VMM, &mut_dump_args));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vmmctl.process(mut_args, mut_ioctl));
                    };
                };
            };
        };

        bsl::ut_scenario{"dump fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmmctl::vmmctl_main mut_vmmctl{};
                vmmctl::ioctl_t mut_ioctl{"failure"};
                bsl::array const argv{"dump"};
                bsl::arguments mut_args{bsl::to_umx(argv.size()), argv.data()};
                loader::dump_vmm_args_t mut_dump_args{};
                constexpr auto epos{5_umx};
                constexpr auto spos{5_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_dump_args.debug_ring.epos = epos.get();
                    mut_dump_args.debug_ring.spos = spos.get();
                    bsl::ut_required_step(mut_ioctl.write(loader::DUMP_VMM, &mut_dump_args));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vmmctl.process(mut_args, mut_ioctl));
                    };
                };
            };
        };

        return bsl::ut_success();
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

    static_assert(mk::tests() == bsl::ut_success());
    return mk::tests();
}
