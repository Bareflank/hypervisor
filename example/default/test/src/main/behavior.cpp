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

#include <bf_control_ops.hpp>
#include <bf_syscall_impl.hpp>
#include <bf_syscall_t.hpp>
#include <bootstrap_t.hpp>
#include <fail_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_t.hpp>
#include <vmexit_t.hpp>
#include <vp_pool_t.hpp>
#include <vps_pool_t.hpp>

#include <bsl/ut.hpp>

namespace example
{
    /// @brief stores the bf_syscall_t that this code will use
    // NOLINTNEXTLINE(bsl-non-pod-static)
    extern syscall::bf_syscall_t g_sys;
    /// @brief stores the intrinsic_t that this code will use
    // NOLINTNEXTLINE(bsl-non-pod-static)
    extern intrinsic_t g_intrinsic;

    /// @brief stores the pool of VPs that we will use
    // NOLINTNEXTLINE(bsl-non-pod-static)
    extern vp_pool_t g_vp_pool;
    /// @brief stores the pool of VPSs that we will use
    // NOLINTNEXTLINE(bsl-non-pod-static)
    extern vps_pool_t g_vps_pool;

    /// @brief stores the bootstrap_t that this code will use
    // NOLINTNEXTLINE(bsl-non-pod-static)
    extern bootstrap_t g_bootstrap;
    /// @brief stores the fail_t that this code will use
    // NOLINTNEXTLINE(bsl-non-pod-static)
    extern fail_t g_fail;
    /// @brief stores the vmexit_t that this code will use
    // NOLINTNEXTLINE(bsl-non-pod-static)
    extern vmexit_t g_vmexit;

    /// <!-- description -->
    ///   @brief Implements the bootstrap entry function. This function is
    ///     called on each PP while the hypervisor is being bootstrapped.
    ///
    /// <!-- inputs/outputs -->
    ///   @param ppid the physical process to bootstrap
    ///
    extern "C" void bootstrap_entry(syscall::bf_uint16_t::value_type const ppid) noexcept;

    /// <!-- description -->
    ///   @brief Implements the VMExit entry function. This is registered
    ///     by the main function to execute whenever a VMExit occurs.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vpsid the ID of the VPS that generated the VMExit
    ///   @param exit_reason the exit reason associated with the VMExit
    ///
    extern "C" void vmexit_entry(
        syscall::bf_uint16_t::value_type const vpsid,
        syscall::bf_uint64_t::value_type const exit_reason) noexcept;

    /// <!-- description -->
    ///   @brief Implements the fast fail entry function. This is registered
    ///     by the main function to execute whenever a fast fail occurs.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vpsid the ID of the VPS that generated the fail
    ///   @param fail_reason the exit reason associated with the fail
    ///
    extern "C" void fail_entry(
        syscall::bf_uint16_t::value_type const vpsid,
        syscall::bf_status_t::value_type const fail_reason) noexcept;

    /// <!-- description -->
    ///   @brief Implements the main entry function for this example
    ///
    /// <!-- inputs/outputs -->
    ///   @param version the version of the spec implemented by the
    ///     microkernel. This can be used to ensure the extension and the
    ///     microkernel speak the same ABI.
    ///
    extern "C" void ext_main_entry(bsl::uint32 const version) noexcept;

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
        bsl::ut_scenario{"bootstrap_entry success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    syscall::g_bf_control_op_exit_impl_executed = {};
                    g_bootstrap.set_dispatch(bsl::errc_failure);
                    bootstrap_entry({});
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(syscall::g_bf_control_op_exit_impl_executed);
                    };
                };
            };
        };

        bsl::ut_scenario{"bootstrap_entry success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    syscall::g_bf_control_op_exit_impl_executed = {};
                    g_bootstrap.set_dispatch(bsl::errc_success);
                    bootstrap_entry({});
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(syscall::g_bf_control_op_exit_impl_executed);
                    };
                };
            };
        };

        bsl::ut_scenario{"fail_entry success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    syscall::g_bf_control_op_exit_impl_executed = {};
                    g_fail.set_dispatch(bsl::errc_failure);
                    fail_entry({}, {});
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(syscall::g_bf_control_op_exit_impl_executed);
                    };
                };
            };
        };

        bsl::ut_scenario{"fail_entry success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    syscall::g_bf_control_op_exit_impl_executed = {};
                    g_fail.set_dispatch(bsl::errc_success);
                    fail_entry({}, {});
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(syscall::g_bf_control_op_exit_impl_executed);
                    };
                };
            };
        };

        bsl::ut_scenario{"vmexit_entry success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    syscall::g_bf_control_op_exit_impl_executed = {};
                    g_vmexit.set_dispatch(bsl::errc_failure);
                    vmexit_entry({}, {});
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(syscall::g_bf_control_op_exit_impl_executed);
                    };
                };
            };
        };

        bsl::ut_scenario{"vmexit_entry success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    syscall::g_bf_control_op_exit_impl_executed = {};
                    g_vmexit.set_dispatch(bsl::errc_success);
                    vmexit_entry({}, {});
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(syscall::g_bf_control_op_exit_impl_executed);
                    };
                };
            };
        };

        bsl::ut_scenario{"main unsupported version"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    syscall::g_bf_control_op_exit_impl_executed = {};
                    syscall::g_bf_control_op_wait_impl_executed = {};
                    g_sys.set_initialize(bsl::errc_success);
                    g_intrinsic.set_initialize(bsl::errc_success);
                    g_vp_pool.set_initialize(bsl::errc_success);
                    g_vps_pool.set_initialize(bsl::errc_success);
                    g_bootstrap.set_initialize(bsl::errc_success);
                    g_fail.set_initialize(bsl::errc_success);
                    g_vmexit.set_initialize(bsl::errc_success);
                    ext_main_entry({});
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(syscall::g_bf_control_op_exit_impl_executed);
                        bsl::ut_check(!syscall::g_bf_control_op_wait_impl_executed);
                    };
                };
            };
        };

        bsl::ut_scenario{"main bf_syscall_t initialize fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    syscall::g_bf_control_op_exit_impl_executed = {};
                    syscall::g_bf_control_op_wait_impl_executed = {};
                    g_sys.set_initialize(bsl::errc_failure);
                    g_intrinsic.set_initialize(bsl::errc_success);
                    g_vp_pool.set_initialize(bsl::errc_success);
                    g_vps_pool.set_initialize(bsl::errc_success);
                    g_bootstrap.set_initialize(bsl::errc_success);
                    g_fail.set_initialize(bsl::errc_success);
                    g_vmexit.set_initialize(bsl::errc_success);
                    ext_main_entry(syscall::BF_ALL_SPECS_SUPPORTED_VAL.get());
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(syscall::g_bf_control_op_exit_impl_executed);
                        bsl::ut_check(!syscall::g_bf_control_op_wait_impl_executed);
                    };
                };
            };
        };

        bsl::ut_scenario{"main intrinsic_t initialize fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    syscall::g_bf_control_op_exit_impl_executed = {};
                    syscall::g_bf_control_op_wait_impl_executed = {};
                    g_sys.set_initialize(bsl::errc_success);
                    g_intrinsic.set_initialize(bsl::errc_failure);
                    g_vp_pool.set_initialize(bsl::errc_success);
                    g_vps_pool.set_initialize(bsl::errc_success);
                    g_bootstrap.set_initialize(bsl::errc_success);
                    g_fail.set_initialize(bsl::errc_success);
                    g_vmexit.set_initialize(bsl::errc_success);
                    ext_main_entry(syscall::BF_ALL_SPECS_SUPPORTED_VAL.get());
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(syscall::g_bf_control_op_exit_impl_executed);
                        bsl::ut_check(!syscall::g_bf_control_op_wait_impl_executed);
                    };
                };
            };
        };

        bsl::ut_scenario{"main vp_pool_t initialize fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    syscall::g_bf_control_op_exit_impl_executed = {};
                    syscall::g_bf_control_op_wait_impl_executed = {};
                    g_sys.set_initialize(bsl::errc_success);
                    g_intrinsic.set_initialize(bsl::errc_success);
                    g_vp_pool.set_initialize(bsl::errc_failure);
                    g_vps_pool.set_initialize(bsl::errc_success);
                    g_bootstrap.set_initialize(bsl::errc_success);
                    g_fail.set_initialize(bsl::errc_success);
                    g_vmexit.set_initialize(bsl::errc_success);
                    ext_main_entry(syscall::BF_ALL_SPECS_SUPPORTED_VAL.get());
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(syscall::g_bf_control_op_exit_impl_executed);
                        bsl::ut_check(!syscall::g_bf_control_op_wait_impl_executed);
                    };
                };
            };
        };

        bsl::ut_scenario{"main vps_pool_t initialize fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    syscall::g_bf_control_op_exit_impl_executed = {};
                    syscall::g_bf_control_op_wait_impl_executed = {};
                    g_sys.set_initialize(bsl::errc_success);
                    g_intrinsic.set_initialize(bsl::errc_success);
                    g_vp_pool.set_initialize(bsl::errc_success);
                    g_vps_pool.set_initialize(bsl::errc_failure);
                    g_bootstrap.set_initialize(bsl::errc_success);
                    g_fail.set_initialize(bsl::errc_success);
                    g_vmexit.set_initialize(bsl::errc_success);
                    ext_main_entry(syscall::BF_ALL_SPECS_SUPPORTED_VAL.get());
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(syscall::g_bf_control_op_exit_impl_executed);
                        bsl::ut_check(!syscall::g_bf_control_op_wait_impl_executed);
                    };
                };
            };
        };

        bsl::ut_scenario{"main bootstrap_t initialize fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    syscall::g_bf_control_op_exit_impl_executed = {};
                    syscall::g_bf_control_op_wait_impl_executed = {};
                    g_sys.set_initialize(bsl::errc_success);
                    g_intrinsic.set_initialize(bsl::errc_success);
                    g_vp_pool.set_initialize(bsl::errc_success);
                    g_vps_pool.set_initialize(bsl::errc_success);
                    g_bootstrap.set_initialize(bsl::errc_failure);
                    g_fail.set_initialize(bsl::errc_success);
                    g_vmexit.set_initialize(bsl::errc_success);
                    ext_main_entry(syscall::BF_ALL_SPECS_SUPPORTED_VAL.get());
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(syscall::g_bf_control_op_exit_impl_executed);
                        bsl::ut_check(!syscall::g_bf_control_op_wait_impl_executed);
                    };
                };
            };
        };

        bsl::ut_scenario{"main fail_t initialize fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    syscall::g_bf_control_op_exit_impl_executed = {};
                    syscall::g_bf_control_op_wait_impl_executed = {};
                    g_sys.set_initialize(bsl::errc_success);
                    g_intrinsic.set_initialize(bsl::errc_success);
                    g_vp_pool.set_initialize(bsl::errc_success);
                    g_vps_pool.set_initialize(bsl::errc_success);
                    g_bootstrap.set_initialize(bsl::errc_success);
                    g_fail.set_initialize(bsl::errc_failure);
                    g_vmexit.set_initialize(bsl::errc_success);
                    ext_main_entry(syscall::BF_ALL_SPECS_SUPPORTED_VAL.get());
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(syscall::g_bf_control_op_exit_impl_executed);
                        bsl::ut_check(!syscall::g_bf_control_op_wait_impl_executed);
                    };
                };
            };
        };

        bsl::ut_scenario{"main vmexit_t initialize fails"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    syscall::g_bf_control_op_exit_impl_executed = {};
                    syscall::g_bf_control_op_wait_impl_executed = {};
                    g_sys.set_initialize(bsl::errc_success);
                    g_intrinsic.set_initialize(bsl::errc_success);
                    g_vp_pool.set_initialize(bsl::errc_success);
                    g_vps_pool.set_initialize(bsl::errc_success);
                    g_bootstrap.set_initialize(bsl::errc_success);
                    g_fail.set_initialize(bsl::errc_success);
                    g_vmexit.set_initialize(bsl::errc_failure);
                    ext_main_entry(syscall::BF_ALL_SPECS_SUPPORTED_VAL.get());
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(syscall::g_bf_control_op_exit_impl_executed);
                        bsl::ut_check(!syscall::g_bf_control_op_wait_impl_executed);
                    };
                };
            };
        };

        bsl::ut_scenario{"main success"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    syscall::g_bf_control_op_exit_impl_executed = {};
                    syscall::g_bf_control_op_wait_impl_executed = {};
                    g_sys.set_initialize(bsl::errc_success);
                    g_intrinsic.set_initialize(bsl::errc_success);
                    g_vp_pool.set_initialize(bsl::errc_success);
                    g_vps_pool.set_initialize(bsl::errc_success);
                    g_bootstrap.set_initialize(bsl::errc_success);
                    g_fail.set_initialize(bsl::errc_success);
                    g_vmexit.set_initialize(bsl::errc_success);
                    ext_main_entry(syscall::BF_ALL_SPECS_SUPPORTED_VAL.get());
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(!syscall::g_bf_control_op_exit_impl_executed);
                        bsl::ut_check(syscall::g_bf_control_op_wait_impl_executed);
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
