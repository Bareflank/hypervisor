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

#include "../../../mocks/bf_syscall_impl.hpp"

#include <bf_constants.hpp>
#include <bf_types.hpp>
#include <string>

#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unordered_map.hpp>
#include <bsl/ut.hpp>

namespace syscall
{
    // -------------------------------------------------------------------------
    // constants
    // -------------------------------------------------------------------------

    /// @brief stores the answer to all things (in 16 bits)
    constexpr auto ANSWER16{42_u16};
    /// @brief stores the answer to all things (in 64 bits)
    constexpr auto ANSWER64{42_u64};

    // -------------------------------------------------------------------------
    // tests
    // -------------------------------------------------------------------------

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
        bsl::ut_scenario{"quiet dummy_bootstrap_entry"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_u16 const arg0{};
                bsl::ut_then{} = [&]() noexcept {
                    dummy_bootstrap_entry(arg0.get());
                };
            };
        };

        bsl::ut_scenario{"quiet dummy_vmexit_entry"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_u16 const arg0{};
                bsl::safe_u64 const arg1{};
                bsl::ut_then{} = [&]() noexcept {
                    dummy_vmexit_entry(arg0.get(), arg1.get());
                };
            };
        };

        bsl::ut_scenario{"quiet dummy_fail_entry"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_u16 const arg0{};
                bsl::safe_u64 const arg1{};
                bsl::ut_then{} = [&]() noexcept {
                    dummy_fail_entry(arg0.get(), arg1.get());
                };
            };
        };

        bsl::ut_scenario{"bf_tls_rax_impl/bf_tls_set_rax_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_data.clear();
                    bf_tls_set_rax_impl(ANSWER64.get());
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(ANSWER64 == bf_tls_rax_impl());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_rbx_impl/bf_tls_set_rbx_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_data.clear();
                    bf_tls_set_rbx_impl(ANSWER64.get());
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(ANSWER64 == bf_tls_rbx_impl());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_rcx_impl/bf_tls_set_rcx_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_data.clear();
                    bf_tls_set_rcx_impl(ANSWER64.get());
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(ANSWER64 == bf_tls_rcx_impl());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_rdx_impl/bf_tls_set_rdx_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_data.clear();
                    bf_tls_set_rdx_impl(ANSWER64.get());
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(ANSWER64 == bf_tls_rdx_impl());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_rbp_impl/bf_tls_set_rbp_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_data.clear();
                    bf_tls_set_rbp_impl(ANSWER64.get());
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(ANSWER64 == bf_tls_rbp_impl());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_rsi_impl/bf_tls_set_rsi_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_data.clear();
                    bf_tls_set_rsi_impl(ANSWER64.get());
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(ANSWER64 == bf_tls_rsi_impl());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_rdi_impl/bf_tls_set_rdi_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_data.clear();
                    bf_tls_set_rdi_impl(ANSWER64.get());
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(ANSWER64 == bf_tls_rdi_impl());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_r8_impl/bf_tls_set_r8_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_data.clear();
                    bf_tls_set_r8_impl(ANSWER64.get());
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(ANSWER64 == bf_tls_r8_impl());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_r9_impl/bf_tls_set_r9_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_data.clear();
                    bf_tls_set_r9_impl(ANSWER64.get());
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(ANSWER64 == bf_tls_r9_impl());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_r10_impl/bf_tls_set_r10_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_data.clear();
                    bf_tls_set_r10_impl(ANSWER64.get());
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(ANSWER64 == bf_tls_r10_impl());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_r11_impl/bf_tls_set_r11_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_data.clear();
                    bf_tls_set_r11_impl(ANSWER64.get());
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(ANSWER64 == bf_tls_r11_impl());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_r12_impl/bf_tls_set_r12_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_data.clear();
                    bf_tls_set_r12_impl(ANSWER64.get());
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(ANSWER64 == bf_tls_r12_impl());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_r13_impl/bf_tls_set_r13_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_data.clear();
                    bf_tls_set_r13_impl(ANSWER64.get());
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(ANSWER64 == bf_tls_r13_impl());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_r14_impl/bf_tls_set_r14_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_data.clear();
                    bf_tls_set_r14_impl(ANSWER64.get());
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(ANSWER64 == bf_tls_r14_impl());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_r15_impl/bf_tls_set_r15_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_data.clear();
                    bf_tls_set_r15_impl(ANSWER64.get());
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(ANSWER64 == bf_tls_r15_impl());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_extid_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_data.clear();
                    g_mut_data.at("bf_tls_extid") = bsl::to_u64(ANSWER16);
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(ANSWER16 == bf_tls_extid_impl());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_vmid_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_data.clear();
                    g_mut_data.at("bf_tls_vmid") = bsl::to_u64(ANSWER16);
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(ANSWER16 == bf_tls_vmid_impl());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_vpid_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_data.clear();
                    g_mut_data.at("bf_tls_vpid") = bsl::to_u64(ANSWER16);
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(ANSWER16 == bf_tls_vpid_impl());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_vsid_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_data.clear();
                    g_mut_data.at("bf_tls_vsid") = bsl::to_u64(ANSWER16);
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(ANSWER16 == bf_tls_vsid_impl());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_ppid_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_data.clear();
                    g_mut_data.at("bf_tls_ppid") = bsl::to_u64(ANSWER16);
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(ANSWER16 == bf_tls_ppid_impl());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_online_pps_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_data.clear();
                    g_mut_data.at("bf_tls_online_pps") = bsl::to_u64(ANSWER16);
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(ANSWER16 == bf_tls_online_pps_impl());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_control_op_exit_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_bf_control_op_exit_impl_executed = {};
                    bf_control_op_exit_impl();
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(g_mut_bf_control_op_exit_impl_executed);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_control_op_wait_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_bf_control_op_wait_impl_executed = {};
                    bf_control_op_wait_impl();
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(g_mut_bf_control_op_wait_impl_executed);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_handle_op_open_handle_impl invalid arg0"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_handle_op_open_handle_impl({}, {})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_handle_op_open_handle_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_u64 mut_reg0_out{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_handle_op_open_handle_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    g_mut_data.at("bf_handle_op_open_handle_impl_reg0_out") = ANSWER64;
                    bsl::ut_then{} = [&]() noexcept {
                        bf_status_t const ret{
                            bf_handle_op_open_handle_impl({}, mut_reg0_out.data())};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                        bsl::ut_check(mut_reg0_out.is_zero());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_handle_op_open_handle_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_u64 mut_reg0_out{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_data.at("bf_handle_op_open_handle_impl_reg0_out") = ANSWER64;
                    bsl::ut_then{} = [&]() noexcept {
                        bf_status_t const ret{
                            bf_handle_op_open_handle_impl({}, mut_reg0_out.data())};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                        bsl::ut_check(ANSWER64 == mut_reg0_out);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_handle_op_close_handle_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_handle_op_close_handle_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_handle_op_close_handle_impl({})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_handle_op_close_handle_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_handle_op_close_handle_impl({})};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_debug_op_out_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_bf_debug_op_out_impl_executed = {};
                    bf_debug_op_out_impl({}, {});
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(g_mut_bf_debug_op_out_impl_executed);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_debug_op_dump_vm_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_bf_debug_op_dump_vm_impl_executed = {};
                    bf_debug_op_dump_vm_impl({});
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(g_mut_bf_debug_op_dump_vm_impl_executed);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_debug_op_dump_vp_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_bf_debug_op_dump_vp_impl_executed = {};
                    bf_debug_op_dump_vp_impl({});
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(g_mut_bf_debug_op_dump_vp_impl_executed);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_debug_op_dump_vs_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_bf_debug_op_dump_vs_impl_executed = {};
                    bf_debug_op_dump_vs_impl({});
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(g_mut_bf_debug_op_dump_vs_impl_executed);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_debug_op_dump_vmexit_log_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_bf_debug_op_dump_vmexit_log_impl_executed = {};
                    bf_debug_op_dump_vmexit_log_impl({});
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(g_mut_bf_debug_op_dump_vmexit_log_impl_executed);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_debug_op_dump_vmexit_log_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_bf_debug_op_dump_vmexit_log_impl_executed = {};
                    bf_debug_op_dump_vmexit_log_impl({});
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(g_mut_bf_debug_op_dump_vmexit_log_impl_executed);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_debug_op_write_c_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_bf_debug_op_write_c_impl_executed = {};
                    bf_debug_op_write_c_impl({});
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(g_mut_bf_debug_op_write_c_impl_executed);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_debug_op_write_str_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_bf_debug_op_write_str_impl_executed = {};
                    bf_debug_op_write_str_impl({});
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(g_mut_bf_debug_op_write_str_impl_executed);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_debug_op_dump_ext_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_bf_debug_op_dump_ext_impl_executed = {};
                    bf_debug_op_dump_ext_impl({});
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(g_mut_bf_debug_op_dump_ext_impl_executed);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_debug_op_dump_page_pool_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_bf_debug_op_dump_page_pool_impl_executed = {};
                    bf_debug_op_dump_page_pool_impl();
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(g_mut_bf_debug_op_dump_page_pool_impl_executed);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_debug_op_dump_huge_pool_impl"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_bf_debug_op_dump_huge_pool_impl_executed = {};
                    bf_debug_op_dump_huge_pool_impl();
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(g_mut_bf_debug_op_dump_huge_pool_impl_executed);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_callback_op_register_bootstrap_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_callback_op_register_bootstrap_impl") =
                        BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_callback_op_register_bootstrap_impl({}, {})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_callback_op_register_bootstrap_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_callback_op_register_bootstrap_impl({}, {})};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_callback_op_register_vmexit_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_callback_op_register_vmexit_impl") =
                        BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_callback_op_register_vmexit_impl({}, {})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_callback_op_register_vmexit_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_callback_op_register_vmexit_impl({}, {})};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_callback_op_register_fail_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_callback_op_register_fail_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_callback_op_register_fail_impl({}, {})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_callback_op_register_fail_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_callback_op_register_fail_impl({}, {})};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vm_op_create_vm_impl invalid arg0"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vm_op_create_vm_impl({}, {})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vm_op_create_vm_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_u16 mut_reg0_out{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_vm_op_create_vm_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    g_mut_data.at("bf_vm_op_create_vm_impl_reg0_out") = bsl::to_u64(ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bf_status_t const ret{bf_vm_op_create_vm_impl({}, mut_reg0_out.data())};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                        bsl::ut_check(mut_reg0_out.is_zero());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vm_op_create_vm_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_u16 mut_reg0_out{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_data.at("bf_vm_op_create_vm_impl_reg0_out") = bsl::to_u64(ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bf_status_t const ret{bf_vm_op_create_vm_impl({}, mut_reg0_out.data())};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                        bsl::ut_check(ANSWER16 == mut_reg0_out);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vm_op_destroy_vm_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_vm_op_destroy_vm_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vm_op_destroy_vm_impl({}, {})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vm_op_destroy_vm_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vm_op_destroy_vm_impl({}, {})};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vm_op_map_direct_impl invalid arg0"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_vm_op_map_direct_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vm_op_map_direct_impl({}, {}, {}, {})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vm_op_map_direct_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_vm_op_map_direct_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    void *pmut_mut_ptr{};
                    bsl::ut_then{} = [&]() noexcept {
                        bf_status_t const ret{bf_vm_op_map_direct_impl({}, {}, {}, &pmut_mut_ptr)};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vm_op_map_direct_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    void *pmut_mut_ptr{};
                    bsl::ut_then{} = [&]() noexcept {
                        bf_status_t const ret{bf_vm_op_map_direct_impl({}, {}, {}, &pmut_mut_ptr)};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vm_op_unmap_direct_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_vm_op_unmap_direct_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vm_op_unmap_direct_impl({}, {}, {})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vm_op_unmap_direct_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vm_op_unmap_direct_impl({}, {}, {})};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vm_op_unmap_direct_broadcast_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_vm_op_unmap_direct_broadcast_impl") =
                        BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vm_op_unmap_direct_broadcast_impl({}, {}, {})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vm_op_unmap_direct_broadcast_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vm_op_unmap_direct_broadcast_impl({}, {}, {})};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vp_op_create_vp_impl invalid arg0"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vp_op_create_vp_impl({}, {}, {}, {})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vp_op_create_vp_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_u16 mut_reg0_out{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_vp_op_create_vp_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    g_mut_data.at("bf_vp_op_create_vp_impl_reg0_out") = bsl::to_u64(ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bf_status_t const ret{
                            bf_vp_op_create_vp_impl({}, {}, {}, mut_reg0_out.data())};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                        bsl::ut_check(mut_reg0_out.is_zero());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vp_op_create_vp_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_u16 mut_reg0_out{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_data.at("bf_vp_op_create_vp_impl_reg0_out") = bsl::to_u64(ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bf_status_t const ret{
                            bf_vp_op_create_vp_impl({}, {}, {}, mut_reg0_out.data())};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                        bsl::ut_check(ANSWER16 == mut_reg0_out);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vp_op_destroy_vp_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_vp_op_destroy_vp_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vp_op_destroy_vp_impl({}, {})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vp_op_destroy_vp_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vp_op_destroy_vp_impl({}, {})};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vp_op_migrate_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_vp_op_migrate_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vp_op_migrate_impl({}, {}, {})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vp_op_migrate_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vp_op_migrate_impl({}, {}, {})};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_create_vs_impl invalid arg0"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vs_op_create_vs_impl({}, {}, {}, {})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_create_vs_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_u16 mut_reg0_out{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_vs_op_create_vs_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    g_mut_data.at("bf_vs_op_create_vs_impl_reg0_out") = bsl::to_u64(ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bf_status_t const ret{
                            bf_vs_op_create_vs_impl({}, {}, {}, mut_reg0_out.data())};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                        bsl::ut_check(mut_reg0_out.is_zero());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_create_vs_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_u16 mut_reg0_out{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_data.at("bf_vs_op_create_vs_impl_reg0_out") = bsl::to_u64(ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bf_status_t const ret{
                            bf_vs_op_create_vs_impl({}, {}, {}, mut_reg0_out.data())};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                        bsl::ut_check(ANSWER16 == mut_reg0_out);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_destroy_vs_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_vs_op_destroy_vs_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vs_op_destroy_vs_impl({}, {})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_destroy_vs_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vs_op_destroy_vs_impl({}, {})};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_init_as_root_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_vs_op_init_as_root_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vs_op_init_as_root_impl({}, {})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_init_as_root_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vs_op_init_as_root_impl({}, {})};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_read_impl invalid arg0"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vs_op_read_impl({}, {}, {}, {})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_read_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_u64 mut_reg0_out{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_vs_op_read_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    g_mut_data.at("bf_vs_op_read_impl_reg0_out") = ANSWER64;
                    bsl::ut_then{} = [&]() noexcept {
                        bf_status_t const ret{bf_vs_op_read_impl({}, {}, {}, mut_reg0_out.data())};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                        bsl::ut_check(mut_reg0_out.is_zero());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_read_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_u64 mut_reg0_out{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_data.at("bf_vs_op_read_impl_reg0_out") = ANSWER64;
                    bsl::ut_then{} = [&]() noexcept {
                        bf_status_t const ret{bf_vs_op_read_impl({}, {}, {}, mut_reg0_out.data())};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                        bsl::ut_check(ANSWER64 == mut_reg0_out);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_write_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_vs_op_write_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vs_op_write_impl({}, {}, {}, ANSWER64.get())};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                        bsl::ut_check(g_mut_data.at("bf_vs_op_write_impl").is_zero());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_write_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vs_op_write_impl({}, {}, {}, ANSWER64.get())};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                        bsl::ut_check(g_mut_data.at("bf_vs_op_write_impl") == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_run_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_vs_op_run_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vs_op_run_impl({}, {}, {}, {})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_run_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vs_op_run_impl({}, {}, {}, {})};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_run_current_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_vs_op_run_current_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vs_op_run_current_impl({})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_run_current_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vs_op_run_current_impl({})};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_advance_ip_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_vs_op_advance_ip_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vs_op_advance_ip_impl({}, {})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_advance_ip_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vs_op_advance_ip_impl({}, {})};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_advance_ip_and_run_current_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_vs_op_advance_ip_and_run_current_impl") =
                        BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vs_op_advance_ip_and_run_current_impl({})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_advance_ip_and_run_current_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vs_op_advance_ip_and_run_current_impl({})};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_promote_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_vs_op_promote_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vs_op_promote_impl({}, {})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_promote_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vs_op_promote_impl({}, {})};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_clear_vs_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_vs_op_clear_vs_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vs_op_clear_vs_impl({}, {})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_clear_vs_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_vs_op_clear_vs_impl({}, {})};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_intrinsic_op_rdmsr_impl invalid arg0"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_intrinsic_op_rdmsr_impl({}, {}, {})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_intrinsic_op_rdmsr_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_u64 mut_reg0_out{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_intrinsic_op_rdmsr_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    g_mut_data.at("bf_intrinsic_op_rdmsr_impl_reg0_out") = ANSWER64;
                    bsl::ut_then{} = [&]() noexcept {
                        bf_status_t const ret{
                            bf_intrinsic_op_rdmsr_impl({}, {}, mut_reg0_out.data())};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                        bsl::ut_check(mut_reg0_out.is_zero());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_intrinsic_op_rdmsr_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_u64 mut_reg0_out{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_data.at("bf_intrinsic_op_rdmsr_impl_reg0_out") = ANSWER64;
                    bsl::ut_then{} = [&]() noexcept {
                        bf_status_t const ret{
                            bf_intrinsic_op_rdmsr_impl({}, {}, mut_reg0_out.data())};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                        bsl::ut_check(ANSWER64 == mut_reg0_out);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_intrinsic_op_wrmsr_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_intrinsic_op_wrmsr_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_intrinsic_op_wrmsr_impl({}, {}, ANSWER64.get())};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                        bsl::ut_check(g_mut_data.at("bf_intrinsic_op_wrmsr_impl").is_zero());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_intrinsic_op_wrmsr_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_intrinsic_op_wrmsr_impl({}, {}, ANSWER64.get())};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                        bsl::ut_check(g_mut_data.at("bf_intrinsic_op_wrmsr_impl") == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_alloc_page_impl invalid arg0"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_u64 mut_reg1_out{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = [&]() noexcept {
                        bf_status_t const ret{
                            bf_mem_op_alloc_page_impl({}, {}, mut_reg1_out.data())};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                        bsl::ut_check(mut_reg1_out.is_zero());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_alloc_page_impl invalid arg0"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                void *pmut_mut_reg0_out{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = [&]() noexcept {
                        bf_status_t const ret{
                            bf_mem_op_alloc_page_impl({}, &pmut_mut_reg0_out, {})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                        bsl::ut_check(nullptr == pmut_mut_reg0_out);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_alloc_page_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                void *pmut_mut_reg0_out{};
                bsl::safe_u64 mut_reg1_out{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_mem_op_alloc_page_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = [&]() noexcept {
                        bf_status_t const ret{
                            bf_mem_op_alloc_page_impl({}, &pmut_mut_reg0_out, mut_reg1_out.data())};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                        bsl::ut_check(nullptr == pmut_mut_reg0_out);
                        bsl::ut_check(mut_reg1_out.is_zero());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_alloc_page_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                void *pmut_mut_reg0_out{};
                bsl::safe_u64 mut_reg1_out{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_mem_op_alloc_page_impl") = BF_STATUS_SUCCESS;
                    g_mut_ptrs.at("bf_mem_op_alloc_page_impl_reg0_out") = &pmut_mut_reg0_out;
                    g_mut_data.at("bf_mem_op_alloc_page_impl_reg1_out") = bsl::to_umx(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bf_status_t const ret{
                            bf_mem_op_alloc_page_impl({}, &pmut_mut_reg0_out, mut_reg1_out.data())};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                        bsl::ut_check(&pmut_mut_reg0_out == pmut_mut_reg0_out);
                        bsl::ut_check(ANSWER64 == mut_reg1_out);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_free_page_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_mem_op_free_page_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_mem_op_free_page_impl({}, {})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_free_page_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_mem_op_free_page_impl({}, {})};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_alloc_huge_impl invalid arg0"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_u64 mut_reg1_out{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = [&]() noexcept {
                        bf_status_t const ret{
                            bf_mem_op_alloc_huge_impl({}, {}, {}, mut_reg1_out.data())};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                        bsl::ut_check(mut_reg1_out.is_zero());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_alloc_huge_impl invalid arg0"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                void *pmut_mut_reg0_out{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = [&]() noexcept {
                        bf_status_t const ret{
                            bf_mem_op_alloc_huge_impl({}, {}, &pmut_mut_reg0_out, {})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                        bsl::ut_check(nullptr == pmut_mut_reg0_out);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_alloc_huge_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                void *pmut_mut_reg0_out{};
                bsl::safe_u64 mut_reg1_out{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_mem_op_alloc_huge_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = [&]() noexcept {
                        bf_status_t const ret{bf_mem_op_alloc_huge_impl(
                            {}, {}, &pmut_mut_reg0_out, mut_reg1_out.data())};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                        bsl::ut_check(nullptr == pmut_mut_reg0_out);
                        bsl::ut_check(mut_reg1_out.is_zero());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_alloc_huge_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                void *pmut_mut_reg0_out{};
                bsl::safe_u64 mut_reg1_out{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_mem_op_alloc_huge_impl") = BF_STATUS_SUCCESS;
                    g_mut_ptrs.at("bf_mem_op_alloc_huge_impl_reg0_out") = &pmut_mut_reg0_out;
                    g_mut_data.at("bf_mem_op_alloc_huge_impl_reg1_out") = bsl::to_umx(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bf_status_t const ret{bf_mem_op_alloc_huge_impl(
                            {}, {}, &pmut_mut_reg0_out, mut_reg1_out.data())};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
                        bsl::ut_check(&pmut_mut_reg0_out == pmut_mut_reg0_out);
                        bsl::ut_check(ANSWER64 == mut_reg1_out);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_free_huge_impl failure"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_mem_op_free_huge_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_mem_op_free_huge_impl({}, {})};
                        bsl::ut_check(BF_STATUS_FAILURE_UNKNOWN == ret);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_free_huge_impl success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = []() noexcept {
                        bf_status_t const ret{bf_mem_op_free_huge_impl({}, {})};
                        bsl::ut_check(BF_STATUS_SUCCESS == ret);
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

    static_assert(syscall::tests() == bsl::ut_success());
    return syscall::tests();
}
