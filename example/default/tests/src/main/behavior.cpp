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

#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <tls_t.hpp>

#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace example
{
    /// @brief stores the bf_syscall_t that this code will use
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    extern syscall::bf_syscall_t g_mut_sys;

    /// @brief stores the Global Storage for this extension
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    extern gs_t g_mut_gs;
    /// @brief stores the Thread Local Storage for this extension on this PP
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    extern thread_local tls_t g_mut_tls;

    /// <!-- description -->
    ///   @brief Implements the bootstrap entry function. This function is
    ///     called on each PP while the hypervisor is being bootstrapped.
    ///
    /// <!-- inputs/outputs -->
    ///   @param ppid the physical process to bootstrap
    ///
    extern "C" void bootstrap_entry(bsl::safe_u16::value_type const ppid) noexcept;

    /// <!-- description -->
    ///   @brief Implements the VMExit entry function. This is registered
    ///     by the main function to execute whenever a VMExit occurs.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vsid the ID of the VS that generated the VMExit
    ///   @param exit_reason the exit reason associated with the VMExit
    ///
    extern "C" void vmexit_entry(
        bsl::safe_u16::value_type const vsid, bsl::safe_u64::value_type const exit_reason) noexcept;

    /// <!-- description -->
    ///   @brief Implements the fast fail entry function. This is registered
    ///     by the main function to execute whenever a fast fail occurs.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vsid the ID of the VS that generated the fail
    ///   @param fail_reason the exit reason associated with the fail
    ///
    extern "C" void fail_entry(
        bsl::safe_u16::value_type const vsid, bsl::safe_u64::value_type const fail_reason) noexcept;

    /// <!-- description -->
    ///   @brief Implements the main entry function for this example
    ///
    /// <!-- inputs/outputs -->
    ///   @param version the version of the spec implemented by the
    ///     microkernel. This can be used to ensure the extension and the
    ///     microkernel speak the same ABI.
    ///
    extern "C" void ext_main_entry(bsl::uint32 const version) noexcept;
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

    bsl::ut_scenario{"bootstrap_entry"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            bsl::ut_when{} = []() noexcept {
                example::bootstrap_entry({});
                bsl::ut_then{} = []() noexcept {
                    bsl::ut_check(syscall::g_mut_bf_control_op_exit_impl_executed);
                };
                bsl::ut_cleanup{} = []() noexcept {
                    syscall::g_mut_bf_control_op_exit_impl_executed = {};
                };
            };
        };
    };

    bsl::ut_scenario{"bootstrap_entry fails"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            bsl::ut_when{} = []() noexcept {
                example::g_mut_tls.test_ret = bsl::errc_failure;
                example::bootstrap_entry({});
                bsl::ut_then{} = []() noexcept {
                    bsl::ut_check(syscall::g_mut_bf_control_op_exit_impl_executed);
                };
                bsl::ut_cleanup{} = []() noexcept {
                    syscall::g_mut_bf_control_op_exit_impl_executed = {};
                    example::g_mut_tls.test_ret = {};
                };
            };
        };
    };

    bsl::ut_scenario{"fail_entry"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            bsl::ut_when{} = []() noexcept {
                example::fail_entry({}, {});
                bsl::ut_then{} = []() noexcept {
                    bsl::ut_check(syscall::g_mut_bf_control_op_exit_impl_executed);
                };
                bsl::ut_cleanup{} = []() noexcept {
                    syscall::g_mut_bf_control_op_exit_impl_executed = {};
                };
            };
        };
    };

    bsl::ut_scenario{"fail_entry fails"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            bsl::ut_when{} = []() noexcept {
                example::g_mut_tls.test_ret = bsl::errc_failure;
                example::fail_entry({}, {});
                bsl::ut_then{} = []() noexcept {
                    bsl::ut_check(syscall::g_mut_bf_control_op_exit_impl_executed);
                };
                bsl::ut_cleanup{} = []() noexcept {
                    syscall::g_mut_bf_control_op_exit_impl_executed = {};
                    example::g_mut_tls.test_ret = {};
                };
            };
        };
    };

    bsl::ut_scenario{"vmexit_entry"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            bsl::ut_when{} = []() noexcept {
                example::vmexit_entry({}, {});
                bsl::ut_then{} = []() noexcept {
                    bsl::ut_check(syscall::g_mut_bf_control_op_exit_impl_executed);
                };
                bsl::ut_cleanup{} = []() noexcept {
                    syscall::g_mut_bf_control_op_exit_impl_executed = {};
                };
            };
        };
    };

    bsl::ut_scenario{"vmexit_entry fails"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            bsl::ut_when{} = []() noexcept {
                example::g_mut_tls.test_ret = bsl::errc_failure;
                example::vmexit_entry({}, {});
                bsl::ut_then{} = []() noexcept {
                    bsl::ut_check(syscall::g_mut_bf_control_op_exit_impl_executed);
                };
                bsl::ut_cleanup{} = []() noexcept {
                    syscall::g_mut_bf_control_op_exit_impl_executed = {};
                    example::g_mut_tls.test_ret = {};
                };
            };
        };
    };

    bsl::ut_scenario{"main"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            bsl::ut_when{} = []() noexcept {
                example::ext_main_entry(syscall::BF_ALL_SPECS_SUPPORTED_VAL.get());
                bsl::ut_then{} = []() noexcept {
                    bsl::ut_check(!syscall::g_mut_bf_control_op_exit_impl_executed);
                    bsl::ut_check(syscall::g_mut_bf_control_op_wait_impl_executed);
                };
                bsl::ut_cleanup{} = []() noexcept {
                    syscall::g_mut_bf_control_op_exit_impl_executed = {};
                    syscall::g_mut_bf_control_op_wait_impl_executed = {};
                };
            };
        };
    };

    bsl::ut_scenario{"main sys.initialize() fails"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            bsl::ut_when{} = []() noexcept {
                example::g_mut_sys.set_initialize(bsl::errc_failure);
                example::ext_main_entry(syscall::BF_ALL_SPECS_SUPPORTED_VAL.get());
                bsl::ut_then{} = []() noexcept {
                    bsl::ut_check(syscall::g_mut_bf_control_op_exit_impl_executed);
                    bsl::ut_check(!syscall::g_mut_bf_control_op_wait_impl_executed);
                };
                bsl::ut_cleanup{} = []() noexcept {
                    syscall::g_mut_bf_control_op_exit_impl_executed = {};
                    syscall::g_mut_bf_control_op_wait_impl_executed = {};
                    example::g_mut_sys.set_initialize({});
                };
            };
        };
    };

    bsl::ut_scenario{"main gs_initialize() fails"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            bsl::ut_when{} = []() noexcept {
                example::g_mut_gs.test_ret = bsl::errc_failure;
                example::ext_main_entry(syscall::BF_ALL_SPECS_SUPPORTED_VAL.get());
                bsl::ut_then{} = []() noexcept {
                    bsl::ut_check(syscall::g_mut_bf_control_op_exit_impl_executed);
                    bsl::ut_check(!syscall::g_mut_bf_control_op_wait_impl_executed);
                };
                bsl::ut_cleanup{} = []() noexcept {
                    syscall::g_mut_bf_control_op_exit_impl_executed = {};
                    syscall::g_mut_bf_control_op_wait_impl_executed = {};
                    example::g_mut_gs.test_ret = {};
                };
            };
        };
    };

    return bsl::ut_success();
}
