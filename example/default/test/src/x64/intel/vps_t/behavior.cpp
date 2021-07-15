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

#include "../../../../../src/x64/intel/vps_t.hpp"

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
                vps_t mut_vps{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_vps.initialize({}, {}, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vps.initialize({}, {}, {}, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"initialize invalid id #1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t mut_vps{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_vps.initialize({}, {}, {}, {}, bsl::safe_uint16::failure()));
                };
            };
        };

        bsl::ut_scenario{"initialize invalid id #2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t mut_vps{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_vps.initialize({}, {}, {}, {}, syscall::BF_INVALID_ID));
                };
            };
        };

        bsl::ut_scenario{"initialize success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t mut_vps{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vps.initialize({}, {}, {}, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"release executes without initialize"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t mut_vps{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vps.release({}, {}, {}, {});
                };
            };
        };

        bsl::ut_scenario{"release executes with initialize"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t mut_vps{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_vps.initialize({}, {}, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vps.release({}, {}, {}, {});
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate not initialized"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t mut_vps{};
                syscall::bf_syscall_t mut_sys{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_vps.allocate({}, {}, mut_sys, {}, {}, {}));
                };
            };
        };

        bsl::ut_scenario{"allocate already allocated"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t mut_vps{};
                syscall::bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_vps.initialize({}, {}, {}, {}, {}));
                    bsl::ut_required_step(mut_vps.allocate({}, {}, mut_sys, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vps.allocate({}, {}, mut_sys, {}, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate invalid vpid #1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t mut_vps{};
                syscall::bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_vps.initialize({}, {}, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vps.allocate(
                            {}, {}, mut_sys, {}, bsl::safe_uint16::failure(), {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate invalid vpid #2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t mut_vps{};
                syscall::bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_vps.initialize({}, {}, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_vps.allocate({}, {}, mut_sys, {}, syscall::BF_INVALID_ID, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate invalid ppid #1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t mut_vps{};
                syscall::bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_vps.initialize({}, {}, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vps.allocate(
                            {}, {}, mut_sys, {}, {}, bsl::safe_uint16::failure()));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate invalid ppid #2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t mut_vps{};
                syscall::bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_vps.initialize({}, {}, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_vps.allocate({}, {}, mut_sys, {}, {}, syscall::BF_INVALID_ID));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate bf_vps_op_init_as_root fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t mut_vps{};
                syscall::bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_vps.initialize({}, {}, {}, {}, {}));
                    mut_sys.set_bf_vps_op_init_as_root({}, bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vps.allocate({}, {}, mut_sys, {}, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate when ppid does not match mut_vpsid"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t mut_vps{};
                syscall::bf_syscall_t mut_sys{};
                constexpr auto ppid{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_vps.initialize({}, {}, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vps.allocate({}, {}, mut_sys, {}, {}, ppid));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate bf_vps_op_write fails for vpid"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t mut_vps{};
                syscall::bf_syscall_t mut_sys{};
                constexpr auto val{0x1_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_vps.initialize({}, {}, {}, {}, {}));
                    mut_sys.set_bf_vps_op_write(
                        {},
                        syscall::bf_reg_t::bf_reg_t_virtual_processor_identifier,
                        val,
                        bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vps.allocate({}, {}, mut_sys, {}, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate bf_vps_op_write fails for link ptr"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t mut_vps{};
                syscall::bf_syscall_t mut_sys{};
                constexpr auto val{0xFFFFFFFFFFFFFFFF_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_vps.initialize({}, {}, {}, {}, {}));
                    mut_sys.set_bf_vps_op_write(
                        {}, syscall::bf_reg_t::bf_reg_t_vmcs_link_pointer, val, bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vps.allocate({}, {}, mut_sys, {}, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate bf_intrinsic_op_rdmsr fails for pin ctls"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t mut_vps{};
                syscall::bf_syscall_t mut_sys{};
                constexpr auto msr{0x48D_u32};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_vps.initialize({}, {}, {}, {}, {}));
                    mut_sys.set_bf_intrinsic_op_rdmsr(msr, bsl::safe_uint64::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vps.allocate({}, {}, mut_sys, {}, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate bf_vps_op_write fails for pin ctls"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t mut_vps{};
                syscall::bf_syscall_t mut_sys{};
                constexpr auto val{0x0_u64};
                constexpr auto msr{0x48D_u32};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_vps.initialize({}, {}, {}, {}, {}));
                    mut_sys.set_bf_intrinsic_op_rdmsr(msr, {});
                    mut_sys.set_bf_vps_op_write(
                        {},
                        syscall::bf_reg_t::bf_reg_t_pin_based_vm_execution_ctls,
                        val,
                        bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vps.allocate({}, {}, mut_sys, {}, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate bf_intrinsic_op_rdmsr fails for proc ctls"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t mut_vps{};
                syscall::bf_syscall_t mut_sys{};
                constexpr auto msr{0x48E_u32};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_vps.initialize({}, {}, {}, {}, {}));
                    mut_sys.set_bf_intrinsic_op_rdmsr(msr, bsl::safe_uint64::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vps.allocate({}, {}, mut_sys, {}, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate bf_vps_op_write fails for proc ctls"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t mut_vps{};
                syscall::bf_syscall_t mut_sys{};
                constexpr auto val{0x0_u64};
                constexpr auto msr{0x48E_u32};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_vps.initialize({}, {}, {}, {}, {}));
                    mut_sys.set_bf_intrinsic_op_rdmsr(msr, {});
                    mut_sys.set_bf_vps_op_write(
                        {},
                        syscall::bf_reg_t::bf_reg_t_primary_proc_based_vm_execution_ctls,
                        val,
                        bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vps.allocate({}, {}, mut_sys, {}, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate bf_intrinsic_op_rdmsr fails for exit ctls"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t mut_vps{};
                syscall::bf_syscall_t mut_sys{};
                constexpr auto msr{0x48F_u32};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_vps.initialize({}, {}, {}, {}, {}));
                    mut_sys.set_bf_intrinsic_op_rdmsr(msr, bsl::safe_uint64::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vps.allocate({}, {}, mut_sys, {}, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate bf_vps_op_write fails for exit ctls"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t mut_vps{};
                syscall::bf_syscall_t mut_sys{};
                constexpr auto val{0x0_u64};
                constexpr auto msr{0x48F_u32};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_vps.initialize({}, {}, {}, {}, {}));
                    mut_sys.set_bf_intrinsic_op_rdmsr(msr, {});
                    mut_sys.set_bf_vps_op_write(
                        {}, syscall::bf_reg_t::bf_reg_t_vmexit_ctls, val, bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vps.allocate({}, {}, mut_sys, {}, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate bf_intrinsic_op_rdmsr fails for entry ctls"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t mut_vps{};
                syscall::bf_syscall_t mut_sys{};
                constexpr auto msr{0x490_u32};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_vps.initialize({}, {}, {}, {}, {}));
                    mut_sys.set_bf_intrinsic_op_rdmsr(msr, bsl::safe_uint64::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vps.allocate({}, {}, mut_sys, {}, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate bf_vps_op_write fails for entry ctls"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t mut_vps{};
                syscall::bf_syscall_t mut_sys{};
                constexpr auto val{0x0_u64};
                constexpr auto msr{0x490_u32};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_vps.initialize({}, {}, {}, {}, {}));
                    mut_sys.set_bf_intrinsic_op_rdmsr(msr, {});
                    mut_sys.set_bf_vps_op_write(
                        {}, syscall::bf_reg_t::bf_reg_t_vmentry_ctls, val, bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vps.allocate({}, {}, mut_sys, {}, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate bf_intrinsic_op_rdmsr fails for proc ctls2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t mut_vps{};
                syscall::bf_syscall_t mut_sys{};
                constexpr auto msr{0x48B_u32};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_vps.initialize({}, {}, {}, {}, {}));
                    mut_sys.set_bf_intrinsic_op_rdmsr(msr, bsl::safe_uint64::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vps.allocate({}, {}, mut_sys, {}, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate bf_vps_op_write fails for proc ctls2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t mut_vps{};
                syscall::bf_syscall_t mut_sys{};
                constexpr auto val{0x0_u64};
                constexpr auto msr{0x48B_u32};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_vps.initialize({}, {}, {}, {}, {}));
                    mut_sys.set_bf_intrinsic_op_rdmsr(msr, {});
                    mut_sys.set_bf_vps_op_write(
                        {},
                        syscall::bf_reg_t::bf_reg_t_secondary_proc_based_vm_execution_ctls,
                        val,
                        bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vps.allocate({}, {}, mut_sys, {}, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate bf_vps_op_write fails for msr bitmap"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t mut_vps{};
                gs_t mut_gs{};
                syscall::bf_syscall_t mut_sys{};
                constexpr auto val{42_umax};
                bsl::ut_when{} = [&]() noexcept {
                    mut_gs.msr_bitmap_phys = val;
                    bsl::ut_required_step(mut_vps.initialize({}, {}, {}, {}, {}));
                    mut_sys.set_bf_vps_op_write(
                        {},
                        syscall::bf_reg_t::bf_reg_t_address_of_msr_bitmaps,
                        val,
                        bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vps.allocate(mut_gs, {}, mut_sys, {}, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vps_t mut_vps{};
                syscall::bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_vps.initialize({}, {}, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vps.allocate({}, {}, mut_sys, {}, {}, {}));
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
