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

#include "../../../src/vp_t.hpp"

#include <bf_constants.hpp>
#include <tls_t.hpp>

#include <bsl/convert.hpp>
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
        bsl::ut_scenario{"initialize"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vp_t mut_vp{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_vp.initialize({});
                };
            };
        };

        bsl::ut_scenario{"release"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vp_t mut_vp{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vp.initialize({});
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vp.release();
                    };
                };
            };
        };

        bsl::ut_scenario{"release without initialize"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vp_t mut_vp{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_vp.release();
                };
            };
        };

        bsl::ut_scenario{"release after allocate"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vp_t mut_vp{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vp.initialize({});
                    bsl::ut_required_step(mut_vp.allocate({}));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vp.release();
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vp_t mut_vp{};
                constexpr auto vmid{1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vp.initialize({});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vp.allocate(vmid));
                        bsl::ut_check(vmid == mut_vp.assigned_vm());
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vp_t mut_vp{};
                constexpr auto vmid{1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vp.initialize({});
                    bsl::ut_required_step(mut_vp.allocate(vmid));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(vmid == mut_vp.assigned_vm());
                        mut_vp.deallocate();
                        bsl::ut_check(vmid != mut_vp.assigned_vm());
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate without allocate"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vp_t mut_vp{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vp.initialize({});
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vp.deallocate();
                    };
                };
            };
        };

        bsl::ut_scenario{"allocation status functions"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vp_t mut_vp{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vp.is_deallocated());
                        bsl::ut_check(!mut_vp.is_allocated());
                    };

                    mut_vp.initialize({});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vp.is_deallocated());
                        bsl::ut_check(!mut_vp.is_allocated());
                    };

                    bsl::ut_required_step(mut_vp.allocate({}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vp.is_deallocated());
                        bsl::ut_check(mut_vp.is_allocated());
                    };

                    mut_vp.deallocate();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vp.is_deallocated());
                        bsl::ut_check(!mut_vp.is_allocated());
                    };

                    bsl::ut_required_step(mut_vp.allocate({}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vp.is_deallocated());
                        bsl::ut_check(mut_vp.is_allocated());
                    };

                    mut_vp.release();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vp.is_deallocated());
                        bsl::ut_check(!mut_vp.is_allocated());
                    };
                };
            };
        };

        bsl::ut_scenario{"set_active"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vp_t mut_vp{};
                tls_t mut_tls{};
                constexpr auto vpid{1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vp.initialize(vpid);
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(mut_vp.allocate({}));
                    mut_vp.set_active(mut_tls);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(vpid == mut_tls.active_vpid);
                    };
                };
            };
        };

        bsl::ut_scenario{"set_inactive"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vp_t mut_vp{};
                tls_t mut_tls{};
                constexpr auto vpid{1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vp.initialize(vpid);
                    mut_tls.active_vpid = vpid.get();
                    bsl::ut_required_step(mut_vp.allocate({}));
                    mut_vp.set_inactive(mut_tls);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(syscall::BF_INVALID_ID == mut_tls.active_vpid);
                    };
                };
            };
        };

        bsl::ut_scenario{"active status functions"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vp_t mut_vp{};
                tls_t mut_tls{};
                constexpr auto ppid{0_u16};
                constexpr auto online_pps{2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = online_pps.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vp.is_active().is_invalid());
                        bsl::ut_check(!mut_vp.is_active_on_this_pp(mut_tls));
                    };

                    mut_vp.initialize({});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vp.is_active().is_invalid());
                        bsl::ut_check(!mut_vp.is_active_on_this_pp(mut_tls));
                    };

                    bsl::ut_required_step(mut_vp.allocate({}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vp.is_active().is_invalid());
                        bsl::ut_check(!mut_vp.is_active_on_this_pp(mut_tls));
                    };

                    mut_vp.set_active(mut_tls);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(ppid == mut_vp.is_active());
                        bsl::ut_check(mut_vp.is_active_on_this_pp(mut_tls));
                    };

                    mut_vp.set_inactive(mut_tls);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vp.is_active().is_invalid());
                        bsl::ut_check(!mut_vp.is_active_on_this_pp(mut_tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"dump"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vp_t mut_vp{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_vp.dump();
                };
            };
        };

        bsl::ut_scenario{"dump active"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vp_t mut_vp{};
                tls_t mut_tls{};
                constexpr auto online_pps{2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = online_pps.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_vp.initialize({});
                    bsl::ut_required_step(mut_vp.allocate({}));
                    mut_vp.set_active(mut_tls);

                    bsl::ut_then{} = [&]() noexcept {
                        mut_vp.dump();
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
