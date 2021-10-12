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

#include "../../../mocks/ext_t.hpp"

#include <basic_alloc_huge_t.hpp>
#include <basic_alloc_page_t.hpp>
#include <bf_constants.hpp>
#include <tls_t.hpp>

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
        bsl::ut_scenario{"initialize"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_t mut_ext{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_ext.initialize({}, {}, {}, {}, {}));
                };
            };
        };

        bsl::ut_scenario{"release"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_t mut_ext{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_ext.release({}, {}, {});
                };
            };
        };

        bsl::ut_scenario{"id"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_t mut_ext{};
                constexpr auto id{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, id, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(id == mut_ext.id());
                    };
                };
            };
        };

        bsl::ut_scenario{"bootstrap_ip"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_t mut_ext{};
                constexpr auto ip{42_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_ext.set_bootstrap_ip(ip);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(ip == mut_ext.bootstrap_ip());
                    };
                };
            };
        };

        bsl::ut_scenario{"vmexit_ip"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_t mut_ext{};
                constexpr auto ip{42_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_ext.set_vmexit_ip(ip);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(ip == mut_ext.vmexit_ip());
                    };
                };
            };
        };

        bsl::ut_scenario{"fail_ip"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_t mut_ext{};
                constexpr auto ip{42_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_ext.set_fail_ip(ip);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(ip == mut_ext.fail_ip());
                    };
                };
            };
        };

        bsl::ut_scenario{"handle"} = [&]() noexcept {
            bsl::ut_given_at_runtime{} = [&]() noexcept {
                ext_t mut_ext{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(syscall::BF_INVALID_HANDLE == mut_ext.handle());
                    };

                    auto const hndl{mut_ext.open_handle()};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(hndl == mut_ext.handle());
                        bsl::ut_check(mut_ext.is_handle_valid(hndl));
                        bsl::ut_check(mut_ext.open_handle().is_invalid());
                    };

                    mut_ext.close_handle();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(syscall::BF_INVALID_HANDLE == mut_ext.handle());
                        bsl::ut_check(!mut_ext.is_handle_valid(hndl));
                    };

                    mut_ext.close_handle();
                };
            };
        };

        bsl::ut_scenario{"alloc_page"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_t mut_ext{};
                tls_t mut_tls{};
                constexpr auto virt{23_u64};
                constexpr auto phys{42_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.test_virt = virt;
                    mut_tls.test_phys = phys;
                    auto const page{mut_ext.alloc_page(mut_tls, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(virt == page.virt);
                        bsl::ut_check(phys == page.phys);
                    };
                };
            };
        };

        bsl::ut_scenario{"alloc_huge"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_t mut_ext{};
                tls_t mut_tls{};
                constexpr auto virt{23_u64};
                constexpr auto phys{42_u64};
                constexpr auto size{0x1000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.test_virt = virt;
                    mut_tls.test_phys = phys;
                    auto const huge{mut_ext.alloc_huge(mut_tls, {}, {}, size)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(virt == huge.virt);
                        bsl::ut_check(phys == huge.phys);
                    };
                };
            };
        };

        bsl::ut_scenario{"map_page_direct"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_t mut_ext{};
                tls_t mut_tls{};
                constexpr auto virt{23_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.test_virt = virt;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(virt == mut_ext.map_page_direct(mut_tls, {}, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"unmap_page_direct"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_t mut_ext{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_ext.unmap_page_direct({}, {}, {}, {}, {}));
                };
            };
        };

        bsl::ut_scenario{"unmap_page_direct fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_t mut_ext{};
                tls_t mut_tls{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.test_ret = bsl::errc_failure;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_ext.unmap_page_direct(mut_tls, {}, {}, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"signal_vm_created"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_t mut_ext{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_ext.signal_vm_created({}, {}, {}));
                };
            };
        };

        bsl::ut_scenario{"signal_vm_created fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_t mut_ext{};
                tls_t mut_tls{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.test_ret = bsl::errc_failure;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_ext.signal_vm_created(mut_tls, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"signal_vm_destroyed"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_t mut_ext{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_ext.signal_vm_destroyed({}, {}, {});
                };
            };
        };

        bsl::ut_scenario{"signal_vm_active"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_t mut_ext{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_ext.signal_vm_active({}, {}, {});
                };
            };
        };

        bsl::ut_scenario{"start"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_t mut_ext{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_ext.is_started());
                    bsl::ut_check(mut_ext.start({}, {}));
                    bsl::ut_check(mut_ext.is_started());
                };
            };
        };

        bsl::ut_scenario{"start fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_t mut_ext{};
                tls_t mut_tls{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.test_ret = bsl::errc_failure;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_ext.is_started());
                        bsl::ut_check(!mut_ext.start(mut_tls, {}));
                        bsl::ut_check(!mut_ext.is_started());
                    };
                };
            };
        };

        bsl::ut_scenario{"bootstrap"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_t mut_ext{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_ext.bootstrap({}, {}));
                };
            };
        };

        bsl::ut_scenario{"bootstrap fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_t mut_ext{};
                tls_t mut_tls{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.test_ret = bsl::errc_failure;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_ext.bootstrap(mut_tls, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"vmexit"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_t mut_ext{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_ext.vmexit({}, {}, {}));
                };
            };
        };

        bsl::ut_scenario{"vmexit fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_t mut_ext{};
                tls_t mut_tls{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.test_ret = bsl::errc_failure;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_ext.vmexit(mut_tls, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"fail"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_t mut_ext{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_ext.is_executing_fail());
                    bsl::ut_check(mut_ext.fail({}, {}, {}, {}));
                    bsl::ut_check(mut_ext.is_executing_fail());
                };
            };
        };

        bsl::ut_scenario{"fail fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_t mut_ext{};
                tls_t mut_tls{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.test_ret = bsl::errc_failure;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_ext.is_executing_fail());
                        bsl::ut_check(!mut_ext.fail(mut_tls, {}, {}, {}));
                        bsl::ut_check(!mut_ext.is_executing_fail());
                    };
                };
            };
        };

        bsl::ut_scenario{"dump"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_t mut_ext{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_ext.dump({});
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
