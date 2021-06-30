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

#include "../../../../mocks/cpp/bf_syscall_t.hpp"

#include <bsl/discard.hpp>
#include <bsl/ut.hpp>

namespace syscall
{
    // -------------------------------------------------------------------------
    // constants
    // -------------------------------------------------------------------------

    /// @brief stores the answer to all things (in 8 bits)
    constexpr auto ANSWER8{42_u8};
    /// @brief stores the answer to all things (in 16 bits)
    constexpr auto ANSWER16{42_u16};
    /// @brief stores the answer to all things (in 32 bits)
    constexpr auto ANSWER32{42_u32};
    /// @brief stores the answer to all things (in 64 bits)
    constexpr auto ANSWER64{42_u64};

    /// @brief stores a bad address
    constexpr auto BAD_ADDR{0xFFFFFFFFFFFFFFFF_u64};
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
        bsl::ut_scenario{"initialize invalid version #1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.initialize(    // --
                        bf_uint32_t::failure(),       // --
                        &dummy_bootstrap_entry,       // --
                        &dummy_vmexit_entry,          // --
                        &dummy_fail_entry));          // --
                };
            };
        };

        bsl::ut_scenario{"initialize invalid version #2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.initialize(    // --
                        {},                           // --
                        &dummy_bootstrap_entry,       // --
                        &dummy_vmexit_entry,          // --
                        &dummy_fail_entry));          // --
                };
            };
        };

        bsl::ut_scenario{"initialize invalid bootstrap_handler"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.initialize(     // --
                        BF_ALL_SPECS_SUPPORTED_VAL,    // --
                        {},                            // --
                        &dummy_vmexit_entry,           // --
                        &dummy_fail_entry));           // --
                };
            };
        };

        bsl::ut_scenario{"initialize invalid vmexit_handler"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.initialize(     // --
                        BF_ALL_SPECS_SUPPORTED_VAL,    // --
                        &dummy_bootstrap_entry,        // --
                        {},                            // --
                        &dummy_fail_entry));           // --
                };
            };
        };

        bsl::ut_scenario{"initialize invalid fail_handler"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.initialize(     // --
                        BF_ALL_SPECS_SUPPORTED_VAL,    // --
                        &dummy_bootstrap_entry,        // --
                        &dummy_vmexit_entry,           // --
                        {}));                          // --
                };
            };
        };

        bsl::ut_scenario{"initialize bf_is_spec1_supported fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_initialize(bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.initialize(    // --
                            BAD_VERSION,                  // --
                            &dummy_bootstrap_entry,       // --
                            &dummy_vmexit_entry,          // --
                            &dummy_fail_entry));          // --
                    };
                };
            };
        };

        bsl::ut_scenario{"initialize bf_handle_op_open_handle_impl fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_initialize(bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.initialize(
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
                    bf_syscall_t sys{};
                    bsl::ut_when{} = [&]() noexcept {
                        sys.set_initialize(bsl::errc_failure);
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(!sys.initialize(
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
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_initialize(bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.initialize(
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
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_initialize(bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.initialize(     // --
                            BF_ALL_SPECS_SUPPORTED_VAL,    // --
                            &dummy_bootstrap_entry,        // --
                            &dummy_vmexit_entry,           // --
                            &dummy_fail_entry));           // --
                    };
                };
            };
        };

        bsl::ut_scenario{"initialize success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.initialize(
                        BF_ALL_SPECS_SUPPORTED_VAL,
                        &dummy_bootstrap_entry,
                        &dummy_vmexit_entry,
                        &dummy_fail_entry));
                };
            };
        };

        bsl::ut_scenario{"release"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_then{} = [&]() noexcept {
                    sys.release();
                };
            };
        };

        // ---------------------------------------------------------------------
        // TLS ops
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bf_tls_rax/bf_tls_set_rax"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_rax());
                        bsl::ut_check(sys.bf_tls_rax().is_zero());
                    };

                    sys.bf_tls_set_rax(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_rax() == ANSWER64);
                    };

                    sys.bf_tls_set_rax(bf_uint64_t::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_rax() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_rbx/bf_tls_set_rbx"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_rbx());
                        bsl::ut_check(sys.bf_tls_rbx().is_zero());
                    };

                    sys.bf_tls_set_rbx(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_rbx() == ANSWER64);
                    };

                    sys.bf_tls_set_rbx(bf_uint64_t::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_rbx() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_rcx/bf_tls_set_rcx"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_rcx());
                        bsl::ut_check(sys.bf_tls_rcx().is_zero());
                    };

                    sys.bf_tls_set_rcx(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_rcx() == ANSWER64);
                    };

                    sys.bf_tls_set_rcx(bf_uint64_t::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_rcx() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_rdx/bf_tls_set_rdx"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_rdx());
                        bsl::ut_check(sys.bf_tls_rdx().is_zero());
                    };

                    sys.bf_tls_set_rdx(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_rdx() == ANSWER64);
                    };

                    sys.bf_tls_set_rdx(bf_uint64_t::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_rdx() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_rbp/bf_tls_set_rbp"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_rbp());
                        bsl::ut_check(sys.bf_tls_rbp().is_zero());
                    };

                    sys.bf_tls_set_rbp(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_rbp() == ANSWER64);
                    };

                    sys.bf_tls_set_rbp(bf_uint64_t::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_rbp() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_rsi/bf_tls_set_rsi"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_rsi());
                        bsl::ut_check(sys.bf_tls_rsi().is_zero());
                    };

                    sys.bf_tls_set_rsi(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_rsi() == ANSWER64);
                    };

                    sys.bf_tls_set_rsi(bf_uint64_t::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_rsi() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_rdi/bf_tls_set_rdi"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_rdi());
                        bsl::ut_check(sys.bf_tls_rdi().is_zero());
                    };

                    sys.bf_tls_set_rdi(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_rdi() == ANSWER64);
                    };

                    sys.bf_tls_set_rdi(bf_uint64_t::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_rdi() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_r8/bf_tls_set_r8"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_r8());
                        bsl::ut_check(sys.bf_tls_r8().is_zero());
                    };

                    sys.bf_tls_set_r8(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_r8() == ANSWER64);
                    };

                    sys.bf_tls_set_r8(bf_uint64_t::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_r8() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_r9/bf_tls_set_r9"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_r9());
                        bsl::ut_check(sys.bf_tls_r9().is_zero());
                    };

                    sys.bf_tls_set_r9(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_r9() == ANSWER64);
                    };

                    sys.bf_tls_set_r9(bf_uint64_t::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_r9() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_r10/bf_tls_set_r10"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_r10());
                        bsl::ut_check(sys.bf_tls_r10().is_zero());
                    };

                    sys.bf_tls_set_r10(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_r10() == ANSWER64);
                    };

                    sys.bf_tls_set_r10(bf_uint64_t::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_r10() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_r11/bf_tls_set_r11"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_r11());
                        bsl::ut_check(sys.bf_tls_r11().is_zero());
                    };

                    sys.bf_tls_set_r11(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_r11() == ANSWER64);
                    };

                    sys.bf_tls_set_r11(bf_uint64_t::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_r11() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_r12/bf_tls_set_r12"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_r12());
                        bsl::ut_check(sys.bf_tls_r12().is_zero());
                    };

                    sys.bf_tls_set_r12(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_r12() == ANSWER64);
                    };

                    sys.bf_tls_set_r12(bf_uint64_t::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_r12() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_r13/bf_tls_set_r13"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_r13());
                        bsl::ut_check(sys.bf_tls_r13().is_zero());
                    };

                    sys.bf_tls_set_r13(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_r13() == ANSWER64);
                    };

                    sys.bf_tls_set_r13(bf_uint64_t::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_r13() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_r14/bf_tls_set_r14"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_r14());
                        bsl::ut_check(sys.bf_tls_r14().is_zero());
                    };

                    sys.bf_tls_set_r14(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_r14() == ANSWER64);
                    };

                    sys.bf_tls_set_r14(bf_uint64_t::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_r14() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_r15/bf_tls_set_r15"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_r15());
                        bsl::ut_check(sys.bf_tls_r15().is_zero());
                    };

                    sys.bf_tls_set_r15(ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_r15() == ANSWER64);
                    };

                    sys.bf_tls_set_r15(bf_uint64_t::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_r15() == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_extid/bf_tls_set_extid"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_extid());
                        bsl::ut_check(sys.bf_tls_extid().is_zero());
                    };

                    sys.bf_tls_set_extid(ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_extid() == ANSWER16);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_vmid/bf_tls_set_vmid"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_vmid());
                        bsl::ut_check(sys.bf_tls_vmid().is_zero());
                    };

                    sys.bf_tls_set_vmid(ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_vmid() == ANSWER16);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_vpid/bf_tls_set_vpid"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_vpid());
                        bsl::ut_check(sys.bf_tls_vpid().is_zero());
                    };

                    sys.bf_tls_set_vpid(ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_vpid() == ANSWER16);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_vpsid/bf_tls_set_vpsid"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_vpsid());
                        bsl::ut_check(sys.bf_tls_vpsid().is_zero());
                    };

                    sys.bf_tls_set_vpsid(ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_vpsid() == ANSWER16);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_ppid/bf_tls_set_ppid"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_ppid());
                        bsl::ut_check(sys.bf_tls_ppid().is_zero());
                    };

                    sys.bf_tls_set_ppid(ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_ppid() == ANSWER16);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_tls_online_pps/bf_tls_set_online_pps"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_online_pps());
                        bsl::ut_check(sys.bf_tls_online_pps().is_zero());
                    };

                    sys.bf_tls_set_online_pps(ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_tls_online_pps() == ANSWER16);
                    };
                };
            };
        };

        // ---------------------------------------------------------------------
        // bf_vm_ops
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bf_vm_op_create_vm bf_vm_op_create_vm_impl fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vm_op_create_vm(bf_uint16_t::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_vm_op_create_vm());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vm_op_create_vm success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vm_op_create_vm(ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_vm_op_create_vm() == ANSWER16);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vm_op_destroy_vm invalid arg0"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{bf_uint16_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vm_op_destroy_vm(arg0));
                };
            };
        };

        bsl::ut_scenario{"bf_vm_op_destroy_vm bf_vm_op_destroy_vm_impl fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vm_op_destroy_vm(arg0, bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_vm_op_destroy_vm(arg0));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vm_op_destroy_vm success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_vm_op_destroy_vm(arg0));
                };
            };
        };

        // ---------------------------------------------------------------------
        // bf_vp_ops
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bf_vp_op_create_vp invalid arg0"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{bf_uint16_t::failure()};
                bf_uint16_t arg1{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vp_op_create_vp(arg0, arg1));
                };
            };
        };

        bsl::ut_scenario{"bf_vp_op_create_vp invalid arg1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint16_t arg1{bf_uint16_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vp_op_create_vp(arg0, arg1));
                };
            };
        };

        bsl::ut_scenario{"bf_vp_op_create_vp bf_vp_op_create_vp_impl fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint16_t arg1{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vp_op_create_vp(arg0, arg1, bf_uint16_t::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_vp_op_create_vp(arg0, arg1));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vp_op_create_vp success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint16_t arg1{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vp_op_create_vp(arg0, arg1, ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_vp_op_create_vp(arg0, arg1) == ANSWER16);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vp_op_destroy_vp invalid arg0"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{bf_uint16_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vp_op_destroy_vp(arg0));
                };
            };
        };

        bsl::ut_scenario{"bf_vp_op_destroy_vp bf_vp_op_destroy_vp_impl fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vp_op_destroy_vp(arg0, bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_vp_op_destroy_vp(arg0));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vp_op_destroy_vp success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_vp_op_destroy_vp(arg0));
                };
            };
        };

        bsl::ut_scenario{"bf_vp_op_migrate invalid arg0"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{bf_uint16_t::failure()};
                bf_uint16_t arg1{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vp_op_migrate(arg0, arg1));
                };
            };
        };

        bsl::ut_scenario{"bf_vp_op_migrate invalid arg1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint16_t arg1{bf_uint16_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vp_op_migrate(arg0, arg1));
                };
            };
        };

        bsl::ut_scenario{"bf_vp_op_migrate bf_vp_op_migrate_impl fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint16_t arg1{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vp_op_migrate(arg0, arg1, bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_vp_op_migrate(arg0, arg1));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vp_op_migrate success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint16_t arg1{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_vp_op_migrate(arg0, arg1));
                };
            };
        };

        // ---------------------------------------------------------------------
        // bf_vps_ops
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bf_vps_op_create_vps invalid arg0"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{bf_uint16_t::failure()};
                bf_uint16_t arg1{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_create_vps(arg0, arg1));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_create_vps invalid arg1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint16_t arg1{bf_uint16_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_create_vps(arg0, arg1));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_create_vps bf_vps_op_create_vps_impl fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint16_t arg1{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vps_op_create_vps(arg0, arg1, bf_uint16_t::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_vps_op_create_vps(arg0, arg1));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_create_vps success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint16_t arg1{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vps_op_create_vps(arg0, arg1, ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_vps_op_create_vps(arg0, arg1) == ANSWER16);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_destroy_vps invalid arg0"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{bf_uint16_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_destroy_vps(arg0));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_destroy_vps bf_vps_op_destroy_vps_impl fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vps_op_destroy_vps(arg0, bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_vps_op_destroy_vps(arg0));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_destroy_vps success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_vps_op_destroy_vps(arg0));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_init_as_root invalid arg0"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{bf_uint16_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_init_as_root(arg0));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_init_as_root bf_vps_op_init_as_root_impl fails"} =
            []() noexcept {
                bsl::ut_given{} = []() noexcept {
                    bf_syscall_t sys{};
                    bf_uint16_t arg0{};
                    bsl::ut_when{} = [&]() noexcept {
                        sys.set_bf_vps_op_init_as_root(arg0, bsl::errc_failure);
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(!sys.bf_vps_op_init_as_root(arg0));
                        };
                    };
                };
            };

        bsl::ut_scenario{"bf_vps_op_init_as_root success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_vps_op_init_as_root(arg0));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_read8 invalid arg0"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{bf_uint16_t::failure()};
                bf_uint64_t arg1{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_read8(arg0, arg1));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_read8 invalid arg1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{bf_uint64_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_read8(arg0, arg1));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_read8 bf_vps_op_read8_impl fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vps_op_read8(arg0, arg1, bf_uint8_t::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_vps_op_read8(arg0, arg1));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_read8 success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vps_op_read8(arg0, arg1, ANSWER8);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_vps_op_read8(arg0, arg1) == ANSWER8);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_read16 invalid arg0"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{bf_uint16_t::failure()};
                bf_uint64_t arg1{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_read16(arg0, arg1));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_read16 invalid arg1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{bf_uint64_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_read16(arg0, arg1));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_read16 bf_vps_op_read16_impl fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vps_op_read16(arg0, arg1, bf_uint16_t::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_vps_op_read16(arg0, arg1));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_read16 success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vps_op_read16(arg0, arg1, ANSWER16);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_vps_op_read16(arg0, arg1) == ANSWER16);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_read32 invalid arg0"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{bf_uint16_t::failure()};
                bf_uint64_t arg1{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_read32(arg0, arg1));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_read32 invalid arg1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{bf_uint64_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_read32(arg0, arg1));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_read32 bf_vps_op_read32_impl fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vps_op_read32(arg0, arg1, bf_uint32_t::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_vps_op_read32(arg0, arg1));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_read32 success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vps_op_read32(arg0, arg1, ANSWER32);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_vps_op_read32(arg0, arg1) == ANSWER32);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_read64 invalid arg0"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{bf_uint16_t::failure()};
                bf_uint64_t arg1{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_read64(arg0, arg1));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_read64 invalid arg1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{bf_uint64_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_read64(arg0, arg1));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_read64 bf_vps_op_read64_impl fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vps_op_read64(arg0, arg1, bf_uint64_t::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_vps_op_read64(arg0, arg1));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_read64 success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vps_op_read64(arg0, arg1, ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_vps_op_read64(arg0, arg1) == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_write8 invalid arg0"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{bf_uint16_t::failure()};
                bf_uint64_t arg1{};
                bf_uint8_t arg2{ANSWER8};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_write8(arg0, arg1, arg2));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_write8 invalid arg1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{bf_uint64_t::failure()};
                bf_uint8_t arg2{ANSWER8};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_write8(arg0, arg1, arg2));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_write8 invalid arg2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{};
                bf_uint8_t arg2{bf_uint8_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_write8(arg0, arg1, arg2));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_write8 bf_vps_op_write8_impl fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{};
                bf_uint8_t arg2{ANSWER8};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vps_op_write8(arg0, arg1, arg2, bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_vps_op_write8(arg0, arg1, arg2));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_write8 success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{};
                bf_uint8_t arg2{ANSWER8};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_vps_op_write8(arg0, arg1, arg2));
                    bsl::ut_check(sys.bf_vps_op_read8(arg0, arg1) == arg2);
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_write16 invalid arg0"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{bf_uint16_t::failure()};
                bf_uint64_t arg1{};
                bf_uint16_t arg2{ANSWER16};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_write16(arg0, arg1, arg2));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_write16 invalid arg1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{bf_uint64_t::failure()};
                bf_uint16_t arg2{ANSWER16};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_write16(arg0, arg1, arg2));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_write16 invalid arg2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{};
                bf_uint16_t arg2{bf_uint16_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_write16(arg0, arg1, arg2));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_write16 bf_vps_op_write16_impl fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{};
                bf_uint16_t arg2{ANSWER16};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vps_op_write16(arg0, arg1, arg2, bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_vps_op_write16(arg0, arg1, arg2));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_write16 success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{};
                bf_uint16_t arg2{ANSWER16};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_vps_op_write16(arg0, arg1, arg2));
                    bsl::ut_check(sys.bf_vps_op_read16(arg0, arg1) == arg2);
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_write32 invalid arg0"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{bf_uint16_t::failure()};
                bf_uint64_t arg1{};
                bf_uint32_t arg2{ANSWER32};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_write32(arg0, arg1, arg2));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_write32 invalid arg1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{bf_uint64_t::failure()};
                bf_uint32_t arg2{ANSWER32};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_write32(arg0, arg1, arg2));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_write32 invalid arg2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{};
                bf_uint32_t arg2{bf_uint32_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_write32(arg0, arg1, arg2));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_write32 bf_vps_op_write32_impl fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{};
                bf_uint32_t arg2{ANSWER32};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vps_op_write32(arg0, arg1, arg2, bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_vps_op_write32(arg0, arg1, arg2));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_write32 success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{};
                bf_uint32_t arg2{ANSWER32};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_vps_op_write32(arg0, arg1, arg2));
                    bsl::ut_check(sys.bf_vps_op_read32(arg0, arg1) == arg2);
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_write64 invalid arg0"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{bf_uint16_t::failure()};
                bf_uint64_t arg1{};
                bf_uint64_t arg2{ANSWER64};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_write64(arg0, arg1, arg2));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_write64 invalid arg1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{bf_uint64_t::failure()};
                bf_uint64_t arg2{ANSWER64};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_write64(arg0, arg1, arg2));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_write64 invalid arg2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{};
                bf_uint64_t arg2{bf_uint64_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_write64(arg0, arg1, arg2));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_write64 bf_vps_op_write64_impl fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{};
                bf_uint64_t arg2{ANSWER64};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vps_op_write64(arg0, arg1, arg2, bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_vps_op_write64(arg0, arg1, arg2));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_write64 success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint64_t arg1{};
                bf_uint64_t arg2{ANSWER64};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_vps_op_write64(arg0, arg1, arg2));
                    bsl::ut_check(sys.bf_vps_op_read64(arg0, arg1) == arg2);
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_read_reg invalid arg0"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{bf_uint16_t::failure()};
                bf_reg_t arg1{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_read_reg(arg0, arg1));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_read_reg bf_vps_op_read_reg_impl fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_reg_t arg1{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vps_op_read_reg(arg0, arg1, bf_uint64_t::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_vps_op_read_reg(arg0, arg1));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_read_reg success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_reg_t arg1{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vps_op_read_reg(arg0, arg1, ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_vps_op_read_reg(arg0, arg1) == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_write_reg invalid arg0"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{bf_uint16_t::failure()};
                bf_reg_t arg1{};
                bf_uint64_t arg2{ANSWER64};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_write_reg(arg0, arg1, arg2));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_write_reg invalid arg2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_reg_t arg1{};
                bf_uint64_t arg2{bf_uint64_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_write_reg(arg0, arg1, arg2));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_write_reg bf_vps_op_write_reg_impl fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_reg_t arg1{};
                bf_uint64_t arg2{ANSWER64};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vps_op_write_reg(arg0, arg1, arg2, bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_vps_op_write_reg(arg0, arg1, arg2));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_write_reg success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_reg_t arg1{};
                bf_uint64_t arg2{ANSWER64};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_vps_op_write_reg(arg0, arg1, arg2));
                    bsl::ut_check(sys.bf_vps_op_read_reg(arg0, arg1) == arg2);
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_run invalid arg0"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{bf_uint16_t::failure()};
                bf_uint16_t arg1{};
                bf_uint16_t arg2{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_run(arg0, arg1, arg2));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_run invalid arg1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint16_t arg1{bf_uint16_t::failure()};
                bf_uint16_t arg2{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_run(arg0, arg1, arg2));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_run invalid arg2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint16_t arg1{};
                bf_uint16_t arg2{bf_uint16_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_run(arg0, arg1, arg2));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_run bf_vps_op_run_impl fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint16_t arg1{};
                bf_uint16_t arg2{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vps_op_run(arg0, arg1, arg2, bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_vps_op_run(arg0, arg1, arg2));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_run success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bf_uint16_t arg1{};
                bf_uint16_t arg2{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_vps_op_run(arg0, arg1, arg2));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_run_current bf_vps_op_run_current_impl fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vps_op_run_current(bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_vps_op_run_current());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_run_current success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_vps_op_run_current());
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_advance_ip invalid arg0"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{bf_uint16_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_advance_ip(arg0));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_advance_ip bf_vps_op_advance_ip_impl fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vps_op_advance_ip(arg0, bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_vps_op_advance_ip(arg0));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_advance_ip success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_vps_op_advance_ip(arg0));
                };
            };
        };

        bsl::ut_scenario{
            "bf_vps_op_advance_ip_and_run_current bf_vps_op_advance_ip_and_run_current_impl "
            "fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vps_op_advance_ip_and_run_current(bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_vps_op_advance_ip_and_run_current());
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_advance_ip_and_run_current success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_vps_op_advance_ip_and_run_current());
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_promote invalid arg0"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{bf_uint16_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_promote(arg0));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_promote bf_vps_op_promote_impl fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vps_op_promote(arg0, bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_vps_op_promote(arg0));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_promote success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_vps_op_promote(arg0));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_clear_vps invalid arg0"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{bf_uint16_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_vps_op_clear_vps(arg0));
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_clear_vps bf_vps_op_clear_vps_impl fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_vps_op_clear_vps(arg0, bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_vps_op_clear_vps(arg0));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vps_op_clear_vps success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint16_t arg0{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_vps_op_clear_vps(arg0));
                };
            };
        };

        // ---------------------------------------------------------------------
        // bf_intrinsic_ops
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bf_intrinsic_op_rdmsr invalid arg0"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint32_t arg0{bf_uint32_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_intrinsic_op_rdmsr(arg0));
                };
            };
        };

        bsl::ut_scenario{"bf_intrinsic_op_rdmsr bf_intrinsic_op_rdmsr_impl fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint32_t arg0{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_intrinsic_op_rdmsr(arg0, bf_uint64_t::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_intrinsic_op_rdmsr(arg0));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_intrinsic_op_rdmsr success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint32_t arg0{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_intrinsic_op_rdmsr(arg0, ANSWER64);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_intrinsic_op_rdmsr(arg0) == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_intrinsic_op_wrmsr invalid arg0"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint32_t arg0{bf_uint32_t::failure()};
                bf_uint64_t arg1{ANSWER64};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_intrinsic_op_wrmsr(arg0, arg1));
                };
            };
        };

        bsl::ut_scenario{"bf_intrinsic_op_wrmsr invalid arg1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint32_t arg0{};
                bf_uint64_t arg1{bf_uint64_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_intrinsic_op_wrmsr(arg0, arg1));
                };
            };
        };

        bsl::ut_scenario{"bf_intrinsic_op_wrmsr bf_intrinsic_op_wrmsr_impl fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint32_t arg0{};
                bf_uint64_t arg1{ANSWER64};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_intrinsic_op_wrmsr(arg0, arg1, bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_intrinsic_op_wrmsr(arg0, arg1));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_intrinsic_op_wrmsr success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint32_t arg0{};
                bf_uint64_t arg1{ANSWER64};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_intrinsic_op_wrmsr(arg0, arg1));
                    bsl::ut_check(sys.bf_intrinsic_op_rdmsr(arg0) == arg1);
                };
            };
        };

        bsl::ut_scenario{"bf_intrinsic_op_invlpga invalid arg0"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t arg0{bf_uint64_t::failure()};
                bf_uint64_t arg1{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_intrinsic_op_invlpga(arg0, arg1));
                };
            };
        };

        bsl::ut_scenario{"bf_intrinsic_op_invlpga invalid arg1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t arg0{};
                bf_uint64_t arg1{bf_uint64_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_intrinsic_op_invlpga(arg0, arg1));
                };
            };
        };

        bsl::ut_scenario{"bf_intrinsic_op_invlpga bf_intrinsic_op_invlpga_impl fails"} =
            []() noexcept {
                bsl::ut_given{} = []() noexcept {
                    bf_syscall_t sys{};
                    bf_uint64_t arg0{};
                    bf_uint64_t arg1{};
                    bsl::ut_when{} = [&]() noexcept {
                        sys.set_bf_intrinsic_op_invlpga(arg0, arg1, bsl::errc_failure);
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(!sys.bf_intrinsic_op_invlpga(arg0, arg1));
                        };
                    };
                };
            };

        bsl::ut_scenario{"bf_intrinsic_op_invlpga success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t arg0{};
                bf_uint64_t arg1{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_intrinsic_op_invlpga(arg0, arg1));
                };
            };
        };

        bsl::ut_scenario{"bf_intrinsic_op_invept invalid arg0"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t arg0{bf_uint64_t::failure()};
                bf_uint64_t arg1{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_intrinsic_op_invept(arg0, arg1));
                };
            };
        };

        bsl::ut_scenario{"bf_intrinsic_op_invept invalid arg1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t arg0{};
                bf_uint64_t arg1{bf_uint64_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_intrinsic_op_invept(arg0, arg1));
                };
            };
        };

        bsl::ut_scenario{"bf_intrinsic_op_invept bf_intrinsic_op_invept_impl fails"} =
            []() noexcept {
                bsl::ut_given{} = []() noexcept {
                    bf_syscall_t sys{};
                    bf_uint64_t arg0{};
                    bf_uint64_t arg1{};
                    bsl::ut_when{} = [&]() noexcept {
                        sys.set_bf_intrinsic_op_invept(arg0, arg1, bsl::errc_failure);
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(!sys.bf_intrinsic_op_invept(arg0, arg1));
                        };
                    };
                };
            };

        bsl::ut_scenario{"bf_intrinsic_op_invept success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t arg0{};
                bf_uint64_t arg1{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_intrinsic_op_invept(arg0, arg1));
                };
            };
        };

        bsl::ut_scenario{"bf_intrinsic_op_invvpid invalid arg0"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t arg0{bf_uint64_t::failure()};
                bf_uint16_t arg1{};
                bf_uint64_t arg2{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_intrinsic_op_invvpid(arg0, arg1, arg2));
                };
            };
        };

        bsl::ut_scenario{"bf_intrinsic_op_invvpid invalid arg1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t arg0{};
                bf_uint16_t arg1{bf_uint16_t::failure()};
                bf_uint64_t arg2{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_intrinsic_op_invvpid(arg0, arg1, arg2));
                };
            };
        };

        bsl::ut_scenario{"bf_intrinsic_op_invvpid invalid arg2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t arg0{};
                bf_uint16_t arg1{};
                bf_uint64_t arg2{bf_uint64_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_intrinsic_op_invvpid(arg0, arg1, arg2));
                };
            };
        };

        bsl::ut_scenario{"bf_intrinsic_op_invvpid bf_intrinsic_op_invvpid_impl fails"} =
            []() noexcept {
                bsl::ut_given{} = []() noexcept {
                    bf_syscall_t sys{};
                    bf_uint64_t arg0{};
                    bf_uint16_t arg1{};
                    bf_uint64_t arg2{};
                    bsl::ut_when{} = [&]() noexcept {
                        sys.set_bf_intrinsic_op_invvpid(arg0, arg1, arg2, bsl::errc_failure);
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(!sys.bf_intrinsic_op_invvpid(arg0, arg1, arg2));
                        };
                    };
                };
            };

        bsl::ut_scenario{"bf_intrinsic_op_invvpid success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t arg0{};
                bf_uint16_t arg1{};
                bf_uint64_t arg2{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_intrinsic_op_invvpid(arg0, arg1, arg2));
                };
            };
        };

        // ---------------------------------------------------------------------
        // bf_mem_ops
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bf_mem_op_alloc_page invalid phys"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{bf_uint64_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_mem_op_alloc_page(phys) == nullptr);
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_alloc_page bf_mem_op_alloc_page_impl fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_mem_op_alloc_page(bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_mem_op_alloc_page(phys) == nullptr);
                        bsl::ut_check(sys.bf_mem_op_alloc_page() == nullptr);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_alloc_page success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{};
                void *ptr{};
                bsl::ut_when{} = [&]() noexcept {
                    ptr = sys.bf_mem_op_alloc_page(phys);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(ptr != nullptr);
                        bsl::ut_check(sys.bf_mem_op_free_page(ptr));
                    };
                };

                bsl::ut_when{} = [&]() noexcept {
                    ptr = sys.bf_mem_op_alloc_page();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(ptr != nullptr);
                        bsl::ut_check(sys.bf_mem_op_free_page(ptr));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_free_page invalid ptr"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                void *ptr{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_mem_op_free_page(ptr));
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_free_page failure/success/failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                void *ptr{};
                bsl::ut_when{} = [&]() noexcept {
                    ptr = sys.bf_mem_op_alloc_page();
                    sys.set_bf_mem_op_free_page(bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_mem_op_free_page(ptr));
                    };

                    sys.set_bf_mem_op_free_page(bsl::errc_success);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_mem_op_free_page(ptr));
                    };

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_mem_op_free_page(ptr));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_alloc_huge invalid size #1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t size{bf_uint64_t::failure()};
                bf_uint64_t phys{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_mem_op_alloc_huge(size, phys) == nullptr);
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_alloc_huge invalid size #2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t size{};
                bf_uint64_t phys{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_mem_op_alloc_huge(size, phys) == nullptr);
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_alloc_huge invalid phys"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t size{ANSWER64};
                bf_uint64_t phys{bf_uint64_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_mem_op_alloc_huge(size, phys) == nullptr);
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_alloc_huge bf_mem_op_alloc_huge_impl fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t size{ANSWER64};
                bf_uint64_t phys{};
                bsl::ut_when{} = [&]() noexcept {
                    sys.set_bf_mem_op_alloc_huge(bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_mem_op_alloc_huge(size, phys) == nullptr);
                        bsl::ut_check(sys.bf_mem_op_alloc_huge(size) == nullptr);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_alloc_huge success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t size{ANSWER64};
                bf_uint64_t phys{};
                void *ptr{};
                bsl::ut_when{} = [&]() noexcept {
                    ptr = sys.bf_mem_op_alloc_huge(size, phys);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(ptr != nullptr);
                        bsl::ut_check(sys.bf_mem_op_free_huge(ptr));
                    };
                };

                bsl::ut_when{} = [&]() noexcept {
                    ptr = sys.bf_mem_op_alloc_huge(size);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(ptr != nullptr);
                        bsl::ut_check(sys.bf_mem_op_free_huge(ptr));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_free_huge invalid ptr"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                void *ptr{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_mem_op_free_huge(ptr));
                };
            };
        };

        bsl::ut_scenario{"bf_mem_op_free_huge failure/success/failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t size{ANSWER64};
                void *ptr{};
                bsl::ut_when{} = [&]() noexcept {
                    ptr = sys.bf_mem_op_alloc_huge(size);
                    sys.set_bf_mem_op_free_huge(bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_mem_op_free_huge(ptr));
                    };

                    sys.set_bf_mem_op_free_huge(bsl::errc_success);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_mem_op_free_huge(ptr));
                    };

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!sys.bf_mem_op_free_huge(ptr));
                    };
                };
            };
        };

        bsl::ut_scenario{"quiet bf_mem_op_alloc_heap"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_mem_op_alloc_heap(ANSWER64) == nullptr);
                };
            };
        };

        // ---------------------------------------------------------------------
        // direct map helpers
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bf_read_phys invalid phys #1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{bf_uint64_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_read_phys<bsl::uint8>(phys));
                };
            };
        };

        bsl::ut_scenario{"bf_read_phys invalid phys #2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_read_phys<bsl::uint8>(phys));
                };
            };
        };

        bsl::ut_scenario{"bf_read_phys address out of range"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{BAD_ADDR};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_read_phys<bsl::uint8>(phys));
                };
            };
        };

        bsl::ut_scenario{"bf_read_phys success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{ANSWER64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(sys.bf_write_phys<bsl::uint8>(phys, ANSWER8));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_read_phys<bsl::uint8>(phys) == ANSWER8);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_read_phys invalid phys #1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{bf_uint64_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_read_phys<bsl::uint16>(phys));
                };
            };
        };

        bsl::ut_scenario{"bf_read_phys invalid phys #2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_read_phys<bsl::uint16>(phys));
                };
            };
        };

        bsl::ut_scenario{"bf_read_phys address out of range"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{BAD_ADDR};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_read_phys<bsl::uint16>(phys));
                };
            };
        };

        bsl::ut_scenario{"bf_read_phys success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{ANSWER64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(sys.bf_write_phys<bsl::uint16>(phys, ANSWER16));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_read_phys<bsl::uint16>(phys) == ANSWER16);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_read_phys invalid phys #1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{bf_uint64_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_read_phys<bsl::uint32>(phys));
                };
            };
        };

        bsl::ut_scenario{"bf_read_phys invalid phys #2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_read_phys<bsl::uint32>(phys));
                };
            };
        };

        bsl::ut_scenario{"bf_read_phys address out of range"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{BAD_ADDR};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_read_phys<bsl::uint32>(phys));
                };
            };
        };

        bsl::ut_scenario{"bf_read_phys success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{ANSWER64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(sys.bf_write_phys<bsl::uint32>(phys, ANSWER32));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_read_phys<bsl::uint32>(phys) == ANSWER32);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_read_phys invalid phys #1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{bf_uint64_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_read_phys<bsl::uint64>(phys));
                };
            };
        };

        bsl::ut_scenario{"bf_read_phys invalid phys #2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_read_phys<bsl::uint64>(phys));
                };
            };
        };

        bsl::ut_scenario{"bf_read_phys address out of range"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{BAD_ADDR};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_read_phys<bsl::uint64>(phys));
                };
            };
        };

        bsl::ut_scenario{"bf_read_phys success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{ANSWER64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(sys.bf_write_phys<bsl::uint64>(phys, ANSWER64));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_read_phys<bsl::uint64>(phys) == ANSWER64);
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_write_phys invalid phys #1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{bf_uint64_t::failure()};
                bf_uint8_t val{ANSWER8};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_write_phys<bsl::uint8>(phys, val));
                };
            };
        };

        bsl::ut_scenario{"bf_write_phys invalid phys #2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{};
                bf_uint8_t val{ANSWER8};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_write_phys<bsl::uint8>(phys, val));
                };
            };
        };

        bsl::ut_scenario{"bf_write_phys invalid val"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{ANSWER64};
                bf_uint8_t val{bf_uint8_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_write_phys<bsl::uint8>(phys, val));
                };
            };
        };

        bsl::ut_scenario{"bf_write_phys address out of range"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{BAD_ADDR};
                bf_uint8_t val{ANSWER8};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_write_phys<bsl::uint8>(phys, val));
                };
            };
        };

        bsl::ut_scenario{"bf_write_phys success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{ANSWER64};
                bf_uint8_t val{ANSWER8};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_write_phys<bsl::uint8>(phys, val));
                    bsl::ut_check(sys.bf_read_phys<bsl::uint8>(phys) == ANSWER8);
                };
            };
        };

        bsl::ut_scenario{"bf_write_phys invalid phys #1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{bf_uint64_t::failure()};
                bf_uint16_t val{ANSWER16};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_write_phys<bsl::uint16>(phys, val));
                };
            };
        };

        bsl::ut_scenario{"bf_write_phys invalid phys #2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{};
                bf_uint16_t val{ANSWER16};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_write_phys<bsl::uint16>(phys, val));
                };
            };
        };

        bsl::ut_scenario{"bf_write_phys invalid val"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{ANSWER64};
                bf_uint16_t val{bf_uint16_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_write_phys<bsl::uint16>(phys, val));
                };
            };
        };

        bsl::ut_scenario{"bf_write_phys address out of range"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{BAD_ADDR};
                bf_uint16_t val{ANSWER16};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_write_phys<bsl::uint16>(phys, val));
                };
            };
        };

        bsl::ut_scenario{"bf_write_phys success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{ANSWER64};
                bf_uint16_t val{ANSWER16};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_write_phys<bsl::uint16>(phys, val));
                    bsl::ut_check(sys.bf_read_phys<bsl::uint16>(phys) == ANSWER16);
                };
            };
        };

        bsl::ut_scenario{"bf_write_phys invalid phys #1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{bf_uint64_t::failure()};
                bf_uint32_t val{ANSWER32};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_write_phys<bsl::uint32>(phys, val));
                };
            };
        };

        bsl::ut_scenario{"bf_write_phys invalid phys #2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{};
                bf_uint32_t val{ANSWER32};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_write_phys<bsl::uint32>(phys, val));
                };
            };
        };

        bsl::ut_scenario{"bf_write_phys invalid val"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{ANSWER64};
                bf_uint32_t val{bf_uint32_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_write_phys<bsl::uint32>(phys, val));
                };
            };
        };

        bsl::ut_scenario{"bf_write_phys address out of range"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{BAD_ADDR};
                bf_uint32_t val{ANSWER32};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_write_phys<bsl::uint32>(phys, val));
                };
            };
        };

        bsl::ut_scenario{"bf_write_phys success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{ANSWER64};
                bf_uint32_t val{ANSWER32};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_write_phys<bsl::uint32>(phys, val));
                    bsl::ut_check(sys.bf_read_phys<bsl::uint32>(phys) == ANSWER32);
                };
            };
        };

        bsl::ut_scenario{"bf_write_phys invalid phys #1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{bf_uint64_t::failure()};
                bf_uint64_t val{ANSWER64};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_write_phys<bsl::uint64>(phys, val));
                };
            };
        };

        bsl::ut_scenario{"bf_write_phys invalid phys #2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{};
                bf_uint64_t val{ANSWER64};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_write_phys<bsl::uint64>(phys, val));
                };
            };
        };

        bsl::ut_scenario{"bf_write_phys invalid val"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{ANSWER64};
                bf_uint64_t val{bf_uint64_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_write_phys<bsl::uint64>(phys, val));
                };
            };
        };

        bsl::ut_scenario{"bf_write_phys address out of range"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{BAD_ADDR};
                bf_uint64_t val{ANSWER64};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_write_phys<bsl::uint64>(phys, val));
                };
            };
        };

        bsl::ut_scenario{"bf_write_phys success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{ANSWER64};
                bf_uint64_t val{ANSWER64};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_write_phys<bsl::uint64>(phys, val));
                    bsl::ut_check(sys.bf_read_phys<bsl::uint64>(phys) == ANSWER64);
                };
            };
        };

        bsl::ut_scenario{"bf_virt_to_phys invalid virt"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                void *virt{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_virt_to_phys(virt));
                };
            };
        };

        bsl::ut_scenario{"bf_virt_to_phys virt not allocated properly"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                void *virt{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!sys.bf_virt_to_phys(&virt));
                };
            };
        };

        bsl::ut_scenario{"bf_virt_to_phys success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                void *virt{};
                bsl::ut_when{} = [&]() noexcept {
                    virt = sys.bf_mem_op_alloc_page();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_virt_to_phys(virt));
                        bsl::ut_check(sys.bf_mem_op_free_page(virt));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_phys_to_virt invalid phys #1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{bf_uint64_t::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_phys_to_virt(phys) == nullptr);
                };
            };
        };

        bsl::ut_scenario{"bf_phys_to_virt invalid phys #2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_phys_to_virt(phys) == nullptr);
                };
            };
        };

        bsl::ut_scenario{"bf_phys_to_virt phys not allocated properly"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                bf_uint64_t phys{ANSWER64};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sys.bf_phys_to_virt(phys) == nullptr);
                };
            };
        };

        bsl::ut_scenario{"bf_phys_to_virt success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bf_syscall_t sys{};
                void *virt{};
                bf_uint64_t phys{ANSWER64};
                bsl::ut_when{} = [&]() noexcept {
                    virt = sys.bf_mem_op_alloc_page(phys);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(sys.bf_phys_to_virt(phys) == virt);
                        bsl::ut_check(sys.bf_mem_op_free_page(virt));
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
