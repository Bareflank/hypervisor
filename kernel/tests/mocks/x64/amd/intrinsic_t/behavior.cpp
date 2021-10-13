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

#include "../../../../../mocks/x64/amd/intrinsic_t.hpp"

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
        bsl::ut_scenario{"tlb_flush"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                intrinsic_t const intrinsic{};
                constexpr auto addr{HYPERVISOR_PAGE_SIZE};
                constexpr auto vpid{0x1_u16};
                bsl::ut_then{} = [&]() noexcept {
                    intrinsic.tlb_flush(addr);
                    intrinsic.tlb_flush(addr, vpid);
                };
            };
        };

        bsl::ut_scenario{"set_rpt"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                intrinsic_t mut_intrinsic{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_intrinsic.set_rpt({});
                };
            };
        };

        bsl::ut_scenario{"set_tp"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                intrinsic_t mut_intrinsic{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_intrinsic.set_tp({});
                };
            };
        };

        bsl::ut_scenario{"set_tls_reg/tls_reg"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                intrinsic_t mut_intrinsic{};
                constexpr auto reg{42_u64};
                constexpr auto val{23_u64};
                bsl::ut_then{} = [&]() noexcept {
                    mut_intrinsic.set_tls_reg(reg, val);
                    bsl::ut_check(val == mut_intrinsic.tls_reg(reg));
                };
            };
        };

        bsl::ut_scenario{"wrmsr/rdmsr"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                intrinsic_t mut_intrinsic{};
                constexpr auto msr{42_u32};
                constexpr auto val{23_u64};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_intrinsic.wrmsr(msr, val));
                    bsl::ut_check(val == mut_intrinsic.rdmsr(msr));
                };
            };
        };

        bsl::ut_scenario{"rdmsr fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                intrinsic_t const intrinsic{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(intrinsic.rdmsr(bsl::safe_u32::max_value()).is_invalid());
                };
            };
        };

        bsl::ut_scenario{"wrmsr fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                intrinsic_t mut_intrinsic{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_intrinsic.wrmsr(bsl::safe_u32::max_value(), {}));
                };
            };
        };

        bsl::ut_scenario{"vmrun"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                intrinsic_t mut_intrinsic{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_intrinsic.vmrun({}, {}, {}, {}, {}));
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
