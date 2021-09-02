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

#include <bsl/array.hpp>
#include <bsl/as_const.hpp>
#include <bsl/convert.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/discard.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Provides the prototype for memset
    ///
    /// <!-- inputs/outputs -->
    ///   @param pmut_dst pointer to the block of memory to fill.
    ///   @param val value to be set. The value is passed as an int, but the
    ///     function fills the block of memory using the unsigned char
    ///     conversion of this value.
    ///   @param num number of bytes to be set to the val.
    ///   @return Returns dst
    ///
    extern "C" [[nodiscard]] auto
    ut_memset(void *const pmut_dst, bsl::int32 const val, bsl::uintmx const num) noexcept -> void *;

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
        bsl::ut_scenario{"copy an array of size 1"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                constexpr auto size{1_umx};
                bsl::array<bsl::uint8, size.get()> mut_data_dst{};
                bsl::ut_when{} = [&]() noexcept {
                    constexpr auto val{42_i32};
                    bsl::discard(
                        ut_memset(mut_data_dst.data(), val.get(), mut_data_dst.size_bytes().get()));
                    bsl::ut_then{} = [&]() noexcept {
                        for (auto const &elem : bsl::as_const(mut_data_dst)) {
                            bsl::ut_check(elem == bsl::to_u8(val));
                        }
                    };
                };
            };
        };

        bsl::ut_scenario{"copy an array of size 15 (unaligned)"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                constexpr auto size{15_umx};
                bsl::array<bsl::uint8, size.get()> mut_data_dst{};
                bsl::ut_when{} = [&]() noexcept {
                    constexpr auto val{42_i32};
                    bsl::discard(
                        ut_memset(mut_data_dst.data(), val.get(), mut_data_dst.size_bytes().get()));
                    bsl::ut_then{} = [&]() noexcept {
                        for (auto const &elem : bsl::as_const(mut_data_dst)) {
                            bsl::ut_check(elem == bsl::to_u8(val));
                        }
                    };
                };
            };
        };

        bsl::ut_scenario{"copy an array of size 16 (aligned)"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                constexpr auto size{16_umx};
                bsl::array<bsl::uint8, size.get()> mut_data_dst{};
                bsl::ut_when{} = [&]() noexcept {
                    constexpr auto val{42_i32};
                    bsl::discard(
                        ut_memset(mut_data_dst.data(), val.get(), mut_data_dst.size_bytes().get()));
                    bsl::ut_then{} = [&]() noexcept {
                        for (auto const &elem : bsl::as_const(mut_data_dst)) {
                            bsl::ut_check(elem == bsl::to_u8(val));
                        }
                    };
                };
            };
        };

        bsl::ut_scenario{"copy an array of size 31 (unaligned)"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                constexpr auto size{31_umx};
                bsl::array<bsl::uint8, size.get()> mut_data_dst{};
                bsl::ut_when{} = [&]() noexcept {
                    constexpr auto val{42_i32};
                    bsl::discard(
                        ut_memset(mut_data_dst.data(), val.get(), mut_data_dst.size_bytes().get()));
                    bsl::ut_then{} = [&]() noexcept {
                        for (auto const &elem : bsl::as_const(mut_data_dst)) {
                            bsl::ut_check(elem == bsl::to_u8(val));
                        }
                    };
                };
            };
        };

        bsl::ut_scenario{"copy an array of size 32 (aligned)"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                constexpr auto size{32_umx};
                bsl::array<bsl::uint8, size.get()> mut_data_dst{};
                bsl::ut_when{} = [&]() noexcept {
                    constexpr auto val{42_i32};
                    bsl::discard(
                        ut_memset(mut_data_dst.data(), val.get(), mut_data_dst.size_bytes().get()));
                    bsl::ut_then{} = [&]() noexcept {
                        for (auto const &elem : bsl::as_const(mut_data_dst)) {
                            bsl::ut_check(elem == bsl::to_u8(val));
                        }
                    };
                };
            };
        };

        bsl::ut_scenario{"copy an array of size 127 (unaligned)"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                constexpr auto size{127_umx};
                bsl::array<bsl::uint8, size.get()> mut_data_dst{};
                bsl::ut_when{} = [&]() noexcept {
                    constexpr auto val{42_i32};
                    bsl::discard(
                        ut_memset(mut_data_dst.data(), val.get(), mut_data_dst.size_bytes().get()));
                    bsl::ut_then{} = [&]() noexcept {
                        for (auto const &elem : bsl::as_const(mut_data_dst)) {
                            bsl::ut_check(elem == bsl::to_u8(val));
                        }
                    };
                };
            };
        };

        bsl::ut_scenario{"copy an array of size 128 (aligned)"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                constexpr auto size{128_umx};
                bsl::array<bsl::uint8, size.get()> mut_data_dst{};
                bsl::ut_when{} = [&]() noexcept {
                    constexpr auto val{42_i32};
                    bsl::discard(
                        ut_memset(mut_data_dst.data(), val.get(), mut_data_dst.size_bytes().get()));
                    bsl::ut_then{} = [&]() noexcept {
                        for (auto const &elem : bsl::as_const(mut_data_dst)) {
                            bsl::ut_check(elem == bsl::to_u8(val));
                        }
                    };
                };
            };
        };

        bsl::ut_scenario{"copy an array of size 0xFFFFF (unaligned)"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                constexpr auto size{0xFFFFF_umx};
                bsl::array<bsl::uint8, size.get()> mut_data_dst{};
                bsl::ut_when{} = [&]() noexcept {
                    constexpr auto val{42_i32};
                    bsl::discard(
                        ut_memset(mut_data_dst.data(), val.get(), mut_data_dst.size_bytes().get()));
                    bsl::ut_then{} = [&]() noexcept {
                        for (auto const &elem : bsl::as_const(mut_data_dst)) {
                            bsl::ut_check(elem == bsl::to_u8(val));
                        }
                    };
                };
            };
        };

        bsl::ut_scenario{"copy an array of size 0x100000 (aligned)"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                constexpr auto size{0x100000_umx};
                bsl::array<bsl::uint8, size.get()> mut_data_dst{};
                bsl::ut_when{} = [&]() noexcept {
                    constexpr auto val{42_i32};
                    bsl::discard(
                        ut_memset(mut_data_dst.data(), val.get(), mut_data_dst.size_bytes().get()));
                    bsl::ut_then{} = [&]() noexcept {
                        for (auto const &elem : bsl::as_const(mut_data_dst)) {
                            bsl::ut_check(elem == bsl::to_u8(val));
                        }
                    };
                };
            };
        };

        bsl::ut_scenario{"memset return"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                constexpr auto size{1_umx};
                bsl::array<bsl::uint8, size.get()> mut_data_dst{};
                bsl::ut_then{} = [&]() noexcept {
                    constexpr auto val{42_i32};
                    bsl::ut_check(
                        ut_memset(
                            mut_data_dst.data(), val.get(), mut_data_dst.size_bytes().get()) ==
                        mut_data_dst.data());
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
