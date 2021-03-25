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

#include "../../../../../src/x64/amd/vps_t.hpp"

#include <bsl/ut.hpp>

namespace example
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
        bsl::ut_scenario{"initialize twice fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t vps{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(vps.initialize(gs, tls, sys, intrinsic, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!vps.initialize(gs, tls, sys, intrinsic, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"initialize invalid id #1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t vps{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_check(
                        !vps.initialize(gs, tls, sys, intrinsic, bsl::safe_uint16::failure()));
                };
            };
        };

        bsl::ut_scenario{"initialize invalid id #2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t vps{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_check(!vps.initialize(gs, tls, sys, intrinsic, syscall::BF_INVALID_ID));
                };
            };
        };

        bsl::ut_scenario{"initialize success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t vps{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_check(vps.initialize(gs, tls, sys, intrinsic, {}));
                };
            };
        };

        bsl::ut_scenario{"release executes without initialize"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t vps{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    vps.release(gs, tls, sys, intrinsic);
                };
            };
        };

        bsl::ut_scenario{"release executes with initialize"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t vps{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(vps.initialize(gs, tls, sys, intrinsic, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        vps.release(gs, tls, sys, intrinsic);
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate not initialized"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t vps{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!vps.allocate(gs, tls, sys, intrinsic, {}, {}));
                };
            };
        };

        bsl::ut_scenario{"allocate already allocated"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t vps{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(vps.initialize(gs, tls, sys, intrinsic, {}));
                    bsl::ut_required_step(vps.allocate(gs, tls, sys, intrinsic, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!vps.allocate(gs, tls, sys, intrinsic, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate invalid vpid #1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t vps{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(vps.initialize(gs, tls, sys, intrinsic, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!vps.allocate(
                            gs, tls, sys, intrinsic, bsl::safe_uint16::failure(), {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate invalid vpid #2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t vps{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(vps.initialize(gs, tls, sys, intrinsic, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !vps.allocate(gs, tls, sys, intrinsic, syscall::BF_INVALID_ID, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate invalid ppid #1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t vps{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(vps.initialize(gs, tls, sys, intrinsic, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!vps.allocate(
                            gs, tls, sys, intrinsic, {}, bsl::safe_uint16::failure()));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate invalid ppid #2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t vps{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(vps.initialize(gs, tls, sys, intrinsic, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !vps.allocate(gs, tls, sys, intrinsic, {}, syscall::BF_INVALID_ID));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate bf_vps_op_init_as_root fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t vps{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(vps.initialize(gs, tls, sys, intrinsic, {}));
                    sys.set_bf_vps_op_init_as_root({}, bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!vps.allocate(gs, tls, sys, intrinsic, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate when ppid does not match vpsid"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t vps{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                constexpr auto ppid{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(vps.initialize(gs, tls, sys, intrinsic, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(vps.allocate(gs, tls, sys, intrinsic, {}, ppid));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate bf_vps_op_write32 fails for asid"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t vps{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                constexpr auto idx{0x0058_u64};
                constexpr auto val{0x1_u32};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(vps.initialize(gs, tls, sys, intrinsic, {}));
                    sys.set_bf_vps_op_write32({}, idx, val, bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!vps.allocate(gs, tls, sys, intrinsic, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate bf_vps_op_write32 fails for intercept 1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t vps{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                constexpr auto idx{0x000C_u64};
                constexpr auto val{0x00040000_u32};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(vps.initialize(gs, tls, sys, intrinsic, {}));
                    sys.set_bf_vps_op_write32({}, idx, val, bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!vps.allocate(gs, tls, sys, intrinsic, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate bf_vps_op_write32 fails for intercept 2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t vps{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                constexpr auto idx{0x0010_u64};
                constexpr auto val{0x00000001_u32};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(vps.initialize(gs, tls, sys, intrinsic, {}));
                    sys.set_bf_vps_op_write32({}, idx, val, bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!vps.allocate(gs, tls, sys, intrinsic, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t vps{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(vps.initialize(gs, tls, sys, intrinsic, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(vps.allocate(gs, tls, sys, intrinsic, {}, {}));
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

    static_assert(example::tests() == bsl::ut_success());
    return example::tests();
}
