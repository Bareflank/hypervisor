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

#include "../../../src/ext_pool_t.hpp"

#include <bfelf/elf64_ehdr_t.hpp>
#include <huge_pool_t.hpp>
#include <intrinsic_t.hpp>
#include <mk_args_t.hpp>
#include <page_pool_t.hpp>
#include <tls_t.hpp>

#include <bsl/errc_type.hpp>
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
                ext_pool_t mut_ext_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        mut_ext_pool.initialize(mut_tls, mut_page_pool, mut_huge_pool, {}, {}));
                };
            };
        };

        bsl::ut_scenario{"initialize with an elf file"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_pool_t mut_ext_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                bfelf::elf64_ehdr_t const file{};
                loader::ext_elf_files_t const elf_files{&file, &file};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_ext_pool.initialize(
                        mut_tls, mut_page_pool, mut_huge_pool, {}, elf_files));
                };
            };
        };

        bsl::ut_scenario{"initialize failure"} = [&]() noexcept {
            bsl::ut_given_at_runtime{} = [&]() noexcept {
                ext_pool_t mut_ext_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                bfelf::elf64_ehdr_t const file{};
                loader::ext_elf_files_t const elf_files{&file, &file};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.test_ret = bsl::errc_failure;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_ext_pool.initialize(
                            mut_tls, mut_page_pool, mut_huge_pool, {}, elf_files));
                    };
                };
            };
        };

        bsl::ut_scenario{"release"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_pool_t mut_ext_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                bfelf::elf64_ehdr_t const file{};
                loader::ext_elf_files_t const elf_files{&file, &file};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext_pool.initialize(
                        mut_tls, mut_page_pool, mut_huge_pool, {}, elf_files));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_ext_pool.release(mut_tls, mut_page_pool, mut_huge_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"release without initialize"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_pool_t mut_ext_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_ext_pool.release(mut_tls, mut_page_pool, mut_huge_pool);
                };
            };
        };

        bsl::ut_scenario{"signal_vm_created"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_pool_t mut_ext_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_ext_pool.signal_vm_created(mut_tls, mut_page_pool, {}));
                };
            };
        };

        bsl::ut_scenario{"signal_vm_created fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_pool_t mut_ext_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_tls.test_ret = bsl::errc_failure;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_ext_pool.signal_vm_created(mut_tls, mut_page_pool, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"signal_vm_destroyed"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_pool_t mut_ext_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_ext_pool.signal_vm_destroyed(mut_tls, mut_page_pool, {});
                };
            };
        };

        bsl::ut_scenario{"signal_vm_active"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_pool_t mut_ext_pool{};
                tls_t mut_tls{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_ext_pool.signal_vm_active(mut_tls, mut_intrinsic, {});
                };
            };
        };

        bsl::ut_scenario{"start"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_pool_t mut_ext_pool{};
                tls_t mut_tls{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_ext_pool.start(mut_tls, mut_intrinsic));
                };
            };
        };

        bsl::ut_scenario{"start fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_pool_t mut_ext_pool{};
                tls_t mut_tls{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_tls.test_ret = bsl::errc_failure;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_ext_pool.start(mut_tls, mut_intrinsic));
                    };
                };
            };
        };

        bsl::ut_scenario{"bootstrap"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_pool_t mut_ext_pool{};
                tls_t mut_tls{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_ext_pool.bootstrap(mut_tls, mut_intrinsic));
                };
            };
        };

        bsl::ut_scenario{"bootstrap fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_pool_t mut_ext_pool{};
                tls_t mut_tls{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_tls.test_ret = bsl::errc_failure;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_ext_pool.bootstrap(mut_tls, mut_intrinsic));
                    };
                };
            };
        };

        bsl::ut_scenario{"dump"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                ext_pool_t mut_ext_pool{};
                tls_t mut_tls{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_ext_pool.dump(mut_tls, {});
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
