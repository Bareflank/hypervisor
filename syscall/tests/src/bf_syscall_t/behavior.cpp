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

#include "../../../src/bf_syscall_t.hpp"

#include <basic_page_4k_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/ut.hpp>

namespace syscall
{
    using page_t = lib::basic_page_4k_t;

    // -------------------------------------------------------------------------
    // constants
    // -------------------------------------------------------------------------

    /// @brief stores the answer to all things (in 16 bits)
    constexpr auto ANSWER16{42_u16};
    /// @brief stores the answer to all things (in 64 bits)
    constexpr auto ANSWER64{42_u64};

    /// @brief stores a bad version
    constexpr auto BAD_VERSION{0x80000000_u32};

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
        bsl::ut_scenario{"initialize bf_is_spec1_supported fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_sys.initialize(    // --
                            BAD_VERSION,                      // --
                            &dummy_bootstrap_entry,           // --
                            &dummy_vmexit_entry,              // --
                            &dummy_fail_entry));              // --
                    };
                };
            };
        };

        bsl::ut_scenario{"initialize bf_handle_op_open_handle_impl fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_errc.at("bf_handle_op_open_handle_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_sys.initialize(
                            BF_ALL_SPECS_SUPPORTED_VAL,    // --
                            &dummy_bootstrap_entry,        // --
                            &dummy_vmexit_entry,           // --
                            &dummy_fail_entry));           // --
                    };
                };
            };
        };

        bsl::ut_scenario{"initialize bf_callback_op_register_bootstrap_impl fails"} =
            []() noexcept {
                bsl::ut_given_at_runtime{} = []() noexcept {
                    bf_syscall_t mut_sys{};
                    bsl::ut_when{} = [&]() noexcept {
                        g_mut_errc.clear();
                        g_mut_errc.at("bf_callback_op_register_bootstrap_impl") =
                            BF_STATUS_FAILURE_UNKNOWN;
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(!mut_sys.initialize(
                                BF_ALL_SPECS_SUPPORTED_VAL,    // --
                                &dummy_bootstrap_entry,        // --
                                &dummy_vmexit_entry,           // --
                                &dummy_fail_entry));           // --
                        };
                    };
                };
            };

        bsl::ut_scenario{"initialize bf_callback_op_register_vmexit_impl fail"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_errc.at("bf_callback_op_register_vmexit_impl") =
                        BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_sys.initialize(
                            BF_ALL_SPECS_SUPPORTED_VAL,    // --
                            &dummy_bootstrap_entry,        // --
                            &dummy_vmexit_entry,           // --
                            &dummy_fail_entry));           // --
                    };
                };
            };
        };

        bsl::ut_scenario{"initialize bf_callback_op_register_fail_impl fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_errc.at("bf_callback_op_register_fail_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_sys.initialize(    // --
                            BF_ALL_SPECS_SUPPORTED_VAL,       // --
                            &dummy_bootstrap_entry,           // --
                            &dummy_vmexit_entry,              // --
                            &dummy_fail_entry));              // --
                    };
                };
            };
        };

        bsl::ut_scenario{"initialize success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.initialize(    // --
                            BF_ALL_SPECS_SUPPORTED_VAL,      // --
                            &dummy_bootstrap_entry,          // --
                            &dummy_vmexit_entry,             // --
                            &dummy_fail_entry));             // --
                    };
                };
            };
        };

        bsl::ut_scenario{"release"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    bsl::ut_then{} = [&]() noexcept {
                        mut_sys.release();
                    };
                };
            };
        };

        // ---------------------------------------------------------------------
        // TLS ops
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bf_tls_rax/bf_tls_set_rax"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_data.clear();

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_rax());
                        bsl::ut_check(mut_sys.bf_tls_rax().is_zero());
                    };

                    mut_sys.bf_tls_set_rax(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_rax() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_rbx/bf_tls_set_rbx"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_data.clear();

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_rbx());
                        bsl::ut_check(mut_sys.bf_tls_rbx().is_zero());
                    };

                    mut_sys.bf_tls_set_rbx(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_rbx() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_rcx/bf_tls_set_rcx"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_data.clear();

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_rcx());
                        bsl::ut_check(mut_sys.bf_tls_rcx().is_zero());
                    };

                    mut_sys.bf_tls_set_rcx(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_rcx() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_rdx/bf_tls_set_rdx"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_data.clear();

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_rdx());
                        bsl::ut_check(mut_sys.bf_tls_rdx().is_zero());
                    };

                    mut_sys.bf_tls_set_rdx(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_rdx() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_rbp/bf_tls_set_rbp"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_data.clear();

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_rbp());
                        bsl::ut_check(mut_sys.bf_tls_rbp().is_zero());
                    };

                    mut_sys.bf_tls_set_rbp(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_rbp() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_rsi/bf_tls_set_rsi"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_data.clear();

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_rsi());
                        bsl::ut_check(mut_sys.bf_tls_rsi().is_zero());
                    };

                    mut_sys.bf_tls_set_rsi(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_rsi() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_rdi/bf_tls_set_rdi"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_data.clear();

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_rdi());
                        bsl::ut_check(mut_sys.bf_tls_rdi().is_zero());
                    };

                    mut_sys.bf_tls_set_rdi(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_rdi() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_r8/bf_tls_set_r8"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_data.clear();

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_r8());
                        bsl::ut_check(mut_sys.bf_tls_r8().is_zero());
                    };

                    mut_sys.bf_tls_set_r8(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_r8() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_r9/bf_tls_set_r9"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_data.clear();

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_r9());
                        bsl::ut_check(mut_sys.bf_tls_r9().is_zero());
                    };

                    mut_sys.bf_tls_set_r9(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_r9() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_r10/bf_tls_set_r10"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_data.clear();

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_r10());
                        bsl::ut_check(mut_sys.bf_tls_r10().is_zero());
                    };

                    mut_sys.bf_tls_set_r10(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_r10() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_r11/bf_tls_set_r11"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_data.clear();

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_r11());
                        bsl::ut_check(mut_sys.bf_tls_r11().is_zero());
                    };

                    mut_sys.bf_tls_set_r11(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_r11() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_r12/bf_tls_set_r12"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_data.clear();

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_r12());
                        bsl::ut_check(mut_sys.bf_tls_r12().is_zero());
                    };

                    mut_sys.bf_tls_set_r12(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_r12() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_r13/bf_tls_set_r13"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_data.clear();

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_r13());
                        bsl::ut_check(mut_sys.bf_tls_r13().is_zero());
                    };

                    mut_sys.bf_tls_set_r13(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_r13() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_r14/bf_tls_set_r14"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_data.clear();

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_r14());
                        bsl::ut_check(mut_sys.bf_tls_r14().is_zero());
                    };

                    mut_sys.bf_tls_set_r14(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_r14() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_r15/bf_tls_set_r15"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_data.clear();

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_r15());
                        bsl::ut_check(mut_sys.bf_tls_r15().is_zero());
                    };

                    mut_sys.bf_tls_set_r15(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_r15() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_extid/bf_tls_set_extid"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_data.clear();

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_extid());
                        bsl::ut_check(mut_sys.bf_tls_extid().is_zero());
                    };

                    g_mut_data.at("bf_tls_extid") = bsl::to_u64(ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_extid() == ANSWER16);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_vmid/bf_tls_set_vmid"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_data.clear();

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_vmid());
                        bsl::ut_check(mut_sys.bf_tls_vmid().is_zero());
                    };

                    g_mut_data.at("bf_tls_vmid") = bsl::to_u64(ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_vmid() == ANSWER16);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_vpid/bf_tls_set_vpid"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_data.clear();

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_vpid());
                        bsl::ut_check(mut_sys.bf_tls_vpid().is_zero());
                    };

                    g_mut_data.at("bf_tls_vpid") = bsl::to_u64(ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_vpid() == ANSWER16);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_vsid/bf_tls_set_vsid"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_data.clear();

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_vsid());
                        bsl::ut_check(mut_sys.bf_tls_vsid().is_zero());
                    };

                    g_mut_data.at("bf_tls_vsid") = bsl::to_u64(ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_vsid() == ANSWER16);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_ppid/bf_tls_set_ppid"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_data.clear();

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_ppid());
                        bsl::ut_check(mut_sys.bf_tls_ppid().is_zero());
                    };

                    g_mut_data.at("bf_tls_ppid") = bsl::to_u64(ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_ppid() == ANSWER16);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_online_pps/bf_tls_set_online_pps"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_data.clear();

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_online_pps());
                        bsl::ut_check(mut_sys.bf_tls_online_pps().is_zero());
                    };

                    g_mut_data.at("bf_tls_online_pps") = bsl::to_u64(ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_tls_online_pps() == ANSWER16);
                    };
                };
            };
        };

        // ---------------------------------------------------------------------
        // bf_vm_ops
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bf_vm_op_create_vm bf_vm_op_create_vm_impl fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_vm_op_create_vm_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    g_mut_data.at("bf_vm_op_create_vm_impl_reg0_out") = bsl::to_u64(ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_vm_op_create_vm().is_invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vm_op_create_vm success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_data.at("bf_vm_op_create_vm_impl_reg0_out") = bsl::to_u64(ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_vm_op_create_vm() == ANSWER16);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vm_op_destroy_vm bf_vm_op_destroy_vm_impl fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u16 const arg0{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_errc.at("bf_vm_op_destroy_vm_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_sys.bf_vm_op_destroy_vm(arg0));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vm_op_destroy_vm success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u16 const arg0{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_vm_op_destroy_vm(arg0));
                    };
                };
            };
        };

        // ---------------------------------------------------------------------
        // bf_vp_ops
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bf_vp_op_create_vp bf_vp_op_create_vp_impl fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u16 const arg0{};
                bsl::safe_u16 const arg1{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_vp_op_create_vp_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    g_mut_data.at("bf_vp_op_create_vp_impl_reg0_out") = bsl::to_u64(ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_vp_op_create_vp(arg0, arg1).is_invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vp_op_create_vp success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u16 const arg0{};
                bsl::safe_u16 const arg1{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_data.at("bf_vp_op_create_vp_impl_reg0_out") = bsl::to_u64(ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_vp_op_create_vp(arg0, arg1) == ANSWER16);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vp_op_destroy_vp bf_vp_op_destroy_vp_impl fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u16 const arg0{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_errc.at("bf_vp_op_destroy_vp_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_sys.bf_vp_op_destroy_vp(arg0));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vp_op_destroy_vp success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u16 const arg0{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_vp_op_destroy_vp(arg0));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vp_op_migrate bf_vp_op_migrate_impl fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u16 const arg0{};
                bsl::safe_u16 const arg1{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_errc.at("bf_vp_op_migrate_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_sys.bf_vp_op_migrate(arg0, arg1));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vp_op_migrate success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u16 const arg0{};
                bsl::safe_u16 const arg1{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_vp_op_migrate(arg0, arg1));
                    };
                };
            };
        };

        // ---------------------------------------------------------------------
        // bf_vs_ops
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bf_vs_op_create_vs bf_vs_op_create_vs_impl fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u16 const arg0{};
                bsl::safe_u16 const arg1{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_vs_op_create_vs_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    g_mut_data.at("bf_vs_op_create_vs_impl_reg0_out") = bsl::to_u64(ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_vs_op_create_vs(arg0, arg1).is_invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_create_vs success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u16 const arg0{};
                bsl::safe_u16 const arg1{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_data.at("bf_vs_op_create_vs_impl_reg0_out") = bsl::to_u64(ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_vs_op_create_vs(arg0, arg1) == ANSWER16);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_destroy_vs bf_vs_op_destroy_vs_impl fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u16 const arg0{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_errc.at("bf_vs_op_destroy_vs_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_sys.bf_vs_op_destroy_vs(arg0));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_destroy_vs success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u16 const arg0{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_vs_op_destroy_vs(arg0));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_init_as_root bf_vs_op_init_as_root_impl fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u16 const arg0{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_errc.at("bf_vs_op_init_as_root_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_sys.bf_vs_op_init_as_root(arg0));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_init_as_root success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u16 const arg0{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_vs_op_init_as_root(arg0));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_read bf_vs_op_read_impl fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u16 const arg0{};
                bf_reg_t const arg1{bf_reg_t::bf_reg_t_dummy};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_vs_op_read_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    g_mut_data.at("bf_vs_op_read_impl_reg0_out") = bsl::to_u64(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_vs_op_read(arg0, arg1).is_invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_read success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u16 const arg0{};
                bf_reg_t const arg1{bf_reg_t::bf_reg_t_dummy};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_data.at("bf_vs_op_read_impl_reg0_out") = ANSWER64;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_vs_op_read(arg0, arg1) == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_write bf_vs_op_write_impl fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u16 const arg0{};
                bf_reg_t const arg1{bf_reg_t::bf_reg_t_dummy};
                bsl::safe_u64 const arg2{ANSWER64};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_vs_op_write_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_sys.bf_vs_op_write(arg0, arg1, arg2));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_write success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u16 const arg0{};
                bf_reg_t const arg1{bf_reg_t::bf_reg_t_dummy};
                bsl::safe_u64 const arg2{ANSWER64};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_vs_op_write(arg0, arg1, arg2));
                        bsl::ut_check(g_mut_data.at("bf_vs_op_write_impl") == arg2);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_run bf_vs_op_run_impl fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u16 const arg0{};
                bsl::safe_u16 const arg1{};
                bsl::safe_u16 const arg2{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_errc.at("bf_vs_op_run_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_sys.bf_vs_op_run(arg0, arg1, arg2));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_run success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u16 const arg0{};
                bsl::safe_u16 const arg1{};
                bsl::safe_u16 const arg2{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_vs_op_run(arg0, arg1, arg2));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_run_current bf_vs_op_run_current_impl fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_errc.at("bf_vs_op_run_current_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_sys.bf_vs_op_run_current());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_run_current success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_vs_op_run_current());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_advance_ip bf_vs_op_advance_ip_impl fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u16 const arg0{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_errc.at("bf_vs_op_advance_ip_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_sys.bf_vs_op_advance_ip(arg0));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_advance_ip success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u16 const arg0{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_vs_op_advance_ip(arg0));
                    };
                };
            };
        };

        bsl::ut_scenario{
            "bf_vs_op_advance_ip_and_run_current bf_vs_op_advance_ip_and_run_current_impl "
            "fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_errc.at("bf_vs_op_advance_ip_and_run_current_impl") =
                        BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_sys.bf_vs_op_advance_ip_and_run_current());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_advance_ip_and_run_current success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_vs_op_advance_ip_and_run_current());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_promote bf_vs_op_promote_impl fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u16 const arg0{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_errc.at("bf_vs_op_promote_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_sys.bf_vs_op_promote(arg0));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_promote success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u16 const arg0{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_vs_op_promote(arg0));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_clear_vs bf_vs_op_clear_vs_impl fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u16 const arg0{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_errc.at("bf_vs_op_clear_vs_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_sys.bf_vs_op_clear_vs(arg0));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_clear_vs success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u16 const arg0{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_vs_op_clear_vs(arg0));
                    };
                };
            };
        };

        // ---------------------------------------------------------------------
        // bf_intrinsic_ops
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bf_intrinsic_op_rdmsr bf_intrinsic_op_rdmsr_impl fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u32 const arg0{bsl::safe_u32::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_intrinsic_op_rdmsr_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    g_mut_data.at("bf_intrinsic_op_rdmsr_impl_reg0_out") = ANSWER64;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_intrinsic_op_rdmsr(arg0).is_invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_intrinsic_op_rdmsr success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u32 const arg0{bsl::safe_u32::magic_1()};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_data.at("bf_intrinsic_op_rdmsr_impl_reg0_out") = ANSWER64;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_intrinsic_op_rdmsr(arg0) == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_intrinsic_op_wrmsr bf_intrinsic_op_wrmsr_impl fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u32 const arg0{bsl::safe_u32::magic_1()};
                bsl::safe_u64 const arg1{ANSWER64};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_intrinsic_op_wrmsr_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_sys.bf_intrinsic_op_wrmsr(arg0, arg1));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_intrinsic_op_wrmsr success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u32 const arg0{bsl::safe_u32::magic_1()};
                bsl::safe_u64 const arg1{ANSWER64};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_intrinsic_op_wrmsr(arg0, arg1));
                        bsl::ut_check(g_mut_data.at("bf_intrinsic_op_wrmsr_impl") == arg1);
                    };
                };
            };
        };

        // ---------------------------------------------------------------------
        // bf_mem_ops
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bf_mem_op_alloc_page bf_mem_op_alloc_page_impl fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u64 mut_phys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_mem_op_alloc_page_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_mem_op_alloc_page<page_t>(mut_phys) == nullptr);
                        bsl::ut_check(mut_sys.bf_mem_op_alloc_page<page_t>() == nullptr);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_alloc_page success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u64 mut_phys{};
                page_t *pmut_mut_ptr{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_ptrs.at("bf_mem_op_alloc_page_impl_reg0_out") = &pmut_mut_ptr;
                    pmut_mut_ptr = mut_sys.bf_mem_op_alloc_page<page_t>(mut_phys);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(pmut_mut_ptr != nullptr);
                        bsl::ut_check(mut_sys.bf_mem_op_free_page(pmut_mut_ptr));
                    };
                };

                bsl::ut_when{} = [&]() noexcept {
                    pmut_mut_ptr = mut_sys.bf_mem_op_alloc_page<page_t>();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(pmut_mut_ptr != nullptr);
                        bsl::ut_check(mut_sys.bf_mem_op_free_page(pmut_mut_ptr));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_free_page failure/success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                page_t *pmut_mut_ptr{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_ptrs.at("bf_mem_op_alloc_page_impl_reg0_out") = &pmut_mut_ptr;

                    pmut_mut_ptr = mut_sys.bf_mem_op_alloc_page<page_t>();
                    g_mut_errc.at("bf_mem_op_free_page_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_sys.bf_mem_op_free_page(pmut_mut_ptr));
                    };

                    g_mut_errc.at("bf_mem_op_free_page_impl") = BF_STATUS_SUCCESS;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_mem_op_free_page(pmut_mut_ptr));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_alloc_huge bf_mem_op_alloc_huge_impl fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u64 const size{HYPERVISOR_PAGE_SIZE};
                bsl::safe_u64 mut_phys{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_errc.at("bf_mem_op_alloc_huge_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mut_sys.bf_mem_op_alloc_huge<page_t>(size, mut_phys) == nullptr);
                        bsl::ut_check(mut_sys.bf_mem_op_alloc_huge<page_t>(size) == nullptr);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_alloc_huge success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u64 const size{HYPERVISOR_PAGE_SIZE};
                bsl::safe_u64 mut_phys{};
                page_t *pmut_mut_ptr{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_ptrs.at("bf_mem_op_alloc_huge_impl_reg0_out") = &pmut_mut_ptr;
                    pmut_mut_ptr = mut_sys.bf_mem_op_alloc_huge<page_t>(size, mut_phys);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(pmut_mut_ptr != nullptr);
                        bsl::ut_check(mut_sys.bf_mem_op_free_huge(pmut_mut_ptr));
                    };
                };

                bsl::ut_when{} = [&]() noexcept {
                    pmut_mut_ptr = mut_sys.bf_mem_op_alloc_huge<page_t>(size);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(pmut_mut_ptr != nullptr);
                        bsl::ut_check(mut_sys.bf_mem_op_free_huge(pmut_mut_ptr));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_free_huge failure/success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t mut_sys{};
                bsl::safe_u64 const size{HYPERVISOR_PAGE_SIZE};
                page_t *pmut_mut_ptr{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_errc.clear();
                    g_mut_data.clear();
                    g_mut_ptrs.at("bf_mem_op_alloc_huge_impl_reg0_out") = &pmut_mut_ptr;

                    pmut_mut_ptr = mut_sys.bf_mem_op_alloc_huge<page_t>(size);
                    g_mut_errc.at("bf_mem_op_free_huge_impl") = BF_STATUS_FAILURE_UNKNOWN;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_sys.bf_mem_op_free_huge(pmut_mut_ptr));
                    };

                    g_mut_errc.at("bf_mem_op_free_huge_impl") = BF_STATUS_SUCCESS;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_sys.bf_mem_op_free_huge(pmut_mut_ptr));
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
