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

#include "../../../mocks/basic_ioctl_t.hpp"

#include <dump_vmm_args_t.hpp>
#include <start_vmm_args_t.hpp>
#include <stop_vmm_args_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace lib
{
    /// <!-- description -->
    ///   @brief Used to execute the actual checks. We put the checks in this
    ///     function so that we can validate the tests both at compile-time
    ///     and at run-time. If a bsl::ut_check fails, the tests will either
    ///     fail fast at run-time, or will produce a compile-time error.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type to test
    ///   @return Always returns bsl::exit_success.
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    tests() noexcept -> bsl::exit_code
    {
        bsl::ut_scenario{"open/close"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                basic_ioctl_t mut_ioctl{"success"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_ioctl.is_open());
                    mut_ioctl.close();
                    bsl::ut_check(!mut_ioctl.is_open());
                };
            };

            bsl::ut_given{} = []() noexcept {
                basic_ioctl_t mut_ioctl{"failure"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_ioctl.is_open());
                };
            };

            bsl::ut_given{} = []() noexcept {
                basic_ioctl_t mut_ioctl{bsl::safe_i32::magic_1()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_ioctl.is_open());
                    mut_ioctl.close();
                    bsl::ut_check(!mut_ioctl.is_open());
                };
            };

            bsl::ut_given{} = []() noexcept {
                basic_ioctl_t mut_ioctl{bsl::safe_i32::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_ioctl.is_open());
                };
            };
        };

        bsl::ut_scenario{"send/read/write"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                basic_ioctl_t mut_ioctl{"success"};
                constexpr auto req{0x1_umx};
                T mut_data{};
                bsl::safe_i64 const i64{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ioctl.send(req).is_neg());
                        bsl::ut_check(mut_ioctl.read(req, &mut_data).is_neg());
                        bsl::ut_check(mut_ioctl.read_write(req, &mut_data).is_neg());

                        bsl::ut_check(!mut_ioctl.write(req, &mut_data).is_neg());
                        bsl::ut_check(!mut_ioctl.write(req, i64).is_neg());

                        bsl::ut_check(!mut_ioctl.send(req).is_neg());
                        bsl::ut_check(!mut_ioctl.read(req, &mut_data).is_neg());
                        bsl::ut_check(!mut_ioctl.read_write(req, &mut_data).is_neg());

                        mut_ioctl.close();

                        bsl::ut_check(mut_ioctl.write(req, &mut_data).is_neg());
                        bsl::ut_check(mut_ioctl.write(req, i64).is_neg());

                        bsl::ut_check(mut_ioctl.send(req).is_neg());
                        bsl::ut_check(mut_ioctl.read(req, &mut_data).is_neg());
                        bsl::ut_check(mut_ioctl.read_write(req, &mut_data).is_neg());
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

    static_assert(lib::tests<loader::start_vmm_args_t>() == bsl::ut_success());
    static_assert(lib::tests<loader::stop_vmm_args_t>() == bsl::ut_success());
    static_assert(lib::tests<loader::dump_vmm_args_t>() == bsl::ut_success());
    static_assert(lib::tests<bsl::safe_i64>() == bsl::ut_success());

    bsl::discard(lib::tests<loader::start_vmm_args_t>());
    bsl::discard(lib::tests<loader::stop_vmm_args_t>());
    bsl::discard(lib::tests<loader::dump_vmm_args_t>());
    bsl::discard(lib::tests<bsl::safe_i64>());

    return bsl::ut_success();
}
