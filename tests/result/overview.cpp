/// @copyright
/// Copyright (C) 2019 Assured Information Security, Inc.
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

#include <bsl/result.hpp>
#include <bsl/reference_wrapper.hpp>
#include <bsl/ut.hpp>

namespace bsl
{
    /// <!-- description -->
    ///   @brief Returns a reference to a global test variable for tracking
    ///     the total number of default constructors that have executed.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @return a reference to a global test variable for tracking
    ///     the total number of default constructors that have executed.
    ///
    template<typename T = void>
    bsl::int64 &
    test_result_monitor_constructor() noexcept
    {
        static bsl::int64 s_test_result_monitor_constructor{};
        return s_test_result_monitor_constructor;
    }

    /// <!-- description -->
    ///   @brief Returns a reference to a global test variable for tracking
    ///     the total number of copy constructors that have executed.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @return a reference to a global test variable for tracking
    ///     the total number of copy constructors that have executed.
    ///
    template<typename T = void>
    bsl::int64 &
    test_result_monitor_copy_constructor() noexcept
    {
        static bsl::int64 s_test_result_monitor_copy_constructor{};
        return s_test_result_monitor_copy_constructor;
    }

    /// <!-- description -->
    ///   @brief Returns a reference to a global test variable for tracking
    ///     the total number of move constructors that have executed.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @return a reference to a global test variable for tracking
    ///     the total number of move constructors that have executed.
    ///
    template<typename T = void>
    bsl::int64 &
    test_result_monitor_move_constructor() noexcept
    {
        static bsl::int64 s_test_result_monitor_move_constructor{};
        return s_test_result_monitor_move_constructor;
    }

    /// <!-- description -->
    ///   @brief Returns a reference to a global test variable for tracking
    ///     the total number of copy assignments that have executed.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @return a reference to a global test variable for tracking
    ///     the total number of copy assignments that have executed.
    ///
    template<typename T = void>
    bsl::int64 &
    test_result_monitor_copy_assignment() noexcept
    {
        static bsl::int64 s_test_result_monitor_copy_assignment{};
        return s_test_result_monitor_copy_assignment;
    }

    /// <!-- description -->
    ///   @brief Returns a reference to a global test variable for tracking
    ///     the total number of move assignments that have executed.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @return a reference to a global test variable for tracking
    ///     the total number of move assignments that have executed.
    ///
    template<typename T = void>
    bsl::int64 &
    test_result_monitor_move_assignment() noexcept
    {
        static bsl::int64 s_test_result_monitor_move_assignment{};
        return s_test_result_monitor_move_assignment;
    }

    /// <!-- description -->
    ///   @brief Returns a reference to a global test variable for tracking
    ///     the total number of destructors that have executed.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @return a reference to a global test variable for tracking
    ///     the total number of destructors that have executed.
    ///
    template<typename T = void>
    bsl::int64 &
    test_result_monitor_destructor() noexcept
    {
        static bsl::int64 s_test_result_monitor_destructor{};
        return s_test_result_monitor_destructor;
    }

    /// <!-- description -->
    ///   @brief Resets all of the stats
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    template<typename T = void>
    void
    test_result_monitor_reset() noexcept
    {
        test_result_monitor_constructor() = 0;
        test_result_monitor_copy_constructor() = 0;
        test_result_monitor_move_constructor() = 0;
        test_result_monitor_copy_assignment() = 0;
        test_result_monitor_move_assignment() = 0;
        test_result_monitor_destructor() = 0;
    }

    /// @class bsl::example_class_base
    ///
    /// <!-- description -->
    ///   @brief A simple class for monitoring construction and assignment
    ///     stats.
    ///
    class test_result_monitor final
    {
    public:
        /// <!-- description -->
        ///   @brief default constructor
        ///
        test_result_monitor() noexcept
        {
            test_result_monitor_constructor()++;
        }

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object to copy
        ///
        test_result_monitor(test_result_monitor const &o) noexcept
        {
            bsl::discard(o);
            test_result_monitor_copy_constructor()++;
        }

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object to copy
        ///
        test_result_monitor(test_result_monitor &&o) noexcept
        {
            bsl::discard(o);
            test_result_monitor_move_constructor()++;
        }

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object to copy
        ///   @return *this
        ///
        [[maybe_unused]] test_result_monitor &
            operator=(test_result_monitor const &o) &
            noexcept
        {
            bsl::discard(o);
            test_result_monitor_copy_assignment()++;

            return *this;
        }

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object to move
        ///   @return *this
        ///
        [[maybe_unused]] test_result_monitor &
            operator=(test_result_monitor &&o) &
            noexcept
        {
            bsl::discard(o);
            test_result_monitor_move_assignment()++;

            return *this;
        }

        /// <!-- description -->
        ///   @brief destructor
        ///
        ~test_result_monitor() noexcept
        {
            test_result_monitor_destructor()++;
        }
    };
}

/// <!-- description -->
///   @brief Main function for this unit test. If a call to ut_check() fails
///     the application will fast fail. If all calls to ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- contracts -->
///   @pre none
///   @post none
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
bsl::exit_code
main() noexcept
{
    using namespace bsl;
    bsl::set_ut_reset_handler(&test_result_monitor_reset);

    bsl::ut_scenario{"make copy t"} = []() {
        bsl::ut_given{} = []() {
            test_result_monitor const t{};
            result<test_result_monitor> const test{t};

            bsl::ut_then{} = [&test]() {
                bsl::ut_check(1 == test_result_monitor_constructor());
                bsl::ut_check(1 == test_result_monitor_copy_constructor());
                bsl::ut_check(0 == test_result_monitor_move_constructor());
                bsl::ut_check(0 == test_result_monitor_copy_assignment());
                bsl::ut_check(0 == test_result_monitor_move_assignment());
                bsl::ut_check(test.success());
                bsl::ut_check(test.errc() == bsl::errc_success);
            };
        };

        bsl::ut_check(2 == test_result_monitor_destructor());
    };

    bsl::ut_scenario{"make move t"} = []() {
        bsl::ut_given{} = []() {
            test_result_monitor t{};
            result<test_result_monitor> const test{bsl::move(t)};

            bsl::ut_then{} = [&test]() {
                bsl::ut_check(1 == test_result_monitor_constructor());
                bsl::ut_check(0 == test_result_monitor_copy_constructor());
                bsl::ut_check(1 == test_result_monitor_move_constructor());
                bsl::ut_check(0 == test_result_monitor_copy_assignment());
                bsl::ut_check(0 == test_result_monitor_move_assignment());
                bsl::ut_check(test.success());
                bsl::ut_check(test.errc() == bsl::errc_success);
            };
        };

        bsl::ut_check(2 == test_result_monitor_destructor());
    };

    bsl::ut_scenario{"make in place"} = []() {
        bsl::ut_given{} = []() {
            result<test_result_monitor> const test{bsl::in_place};

            bsl::ut_then{} = [&test]() {
                bsl::ut_check(1 == test_result_monitor_constructor());
                bsl::ut_check(0 == test_result_monitor_copy_constructor());
                bsl::ut_check(0 == test_result_monitor_move_constructor());
                bsl::ut_check(0 == test_result_monitor_copy_assignment());
                bsl::ut_check(0 == test_result_monitor_move_assignment());
                bsl::ut_check(test.success());
                bsl::ut_check(test.errc() == bsl::errc_success);
            };
        };

        bsl::ut_check(1 == test_result_monitor_destructor());
    };

    bsl::ut_scenario{"make errc"} = []() {
        bsl::ut_given{} = []() {
            bsl::errc_type<> const myerror{42};
            result<test_result_monitor> const test{myerror};

            bsl::ut_then{} = [&test, &myerror]() {
                bsl::ut_check(0 == test_result_monitor_constructor());
                bsl::ut_check(0 == test_result_monitor_copy_constructor());
                bsl::ut_check(0 == test_result_monitor_move_constructor());
                bsl::ut_check(0 == test_result_monitor_copy_assignment());
                bsl::ut_check(0 == test_result_monitor_move_assignment());
                bsl::ut_check(test.failure());
                bsl::ut_check(test.errc() == myerror);
            };
        };

        bsl::ut_check(0 == test_result_monitor_destructor());
    };

    bsl::ut_scenario{"make move"} = []() {
        bsl::ut_given{} = []() {
            bsl::errc_type<> myerror{42};
            result<test_result_monitor> const test{bsl::move(myerror)};

            bsl::ut_then{} = [&test, &myerror]() {
                bsl::ut_check(0 == test_result_monitor_constructor());
                bsl::ut_check(0 == test_result_monitor_copy_constructor());
                bsl::ut_check(0 == test_result_monitor_move_constructor());
                bsl::ut_check(0 == test_result_monitor_copy_assignment());
                bsl::ut_check(0 == test_result_monitor_move_assignment());
                bsl::ut_check(test.failure());
                bsl::ut_check(test.errc() == myerror);
            };
        };

        bsl::ut_check(0 == test_result_monitor_destructor());
    };

    bsl::ut_scenario{"copy with t"} = []() {
        bsl::ut_given{} = []() {
            result<test_result_monitor> const test1{bsl::in_place};
            result<test_result_monitor> const test2{test1};

            bsl::ut_then{} = [&test1, &test2]() {
                bsl::ut_check(1 == test_result_monitor_constructor());
                bsl::ut_check(1 == test_result_monitor_copy_constructor());
                bsl::ut_check(0 == test_result_monitor_move_constructor());
                bsl::ut_check(0 == test_result_monitor_copy_assignment());
                bsl::ut_check(0 == test_result_monitor_move_assignment());
                bsl::ut_check(test1.success());
                bsl::ut_check(test2.success());
            };
        };

        bsl::ut_check(2 == test_result_monitor_destructor());
    };

    bsl::ut_scenario{"copy with errc"} = []() {
        bsl::ut_given{} = []() {
            result<test_result_monitor> const test1{bsl::errc_failure};
            result<test_result_monitor> const test2{test1};

            bsl::ut_then{} = [&test1, &test2]() {
                bsl::ut_check(0 == test_result_monitor_constructor());
                bsl::ut_check(0 == test_result_monitor_copy_constructor());
                bsl::ut_check(0 == test_result_monitor_move_constructor());
                bsl::ut_check(0 == test_result_monitor_copy_assignment());
                bsl::ut_check(0 == test_result_monitor_move_assignment());
                bsl::ut_check(test1.failure());
                bsl::ut_check(test2.failure());
            };
        };

        bsl::ut_check(0 == test_result_monitor_destructor());
    };

    bsl::ut_scenario{"move with t"} = []() {
        bsl::ut_given{} = []() {
            result<test_result_monitor> test1{bsl::in_place};
            result<test_result_monitor> const test2{bsl::move(test1)};

            bsl::ut_then{} = [&test2]() {
                bsl::ut_check(1 == test_result_monitor_constructor());
                bsl::ut_check(0 == test_result_monitor_copy_constructor());
                bsl::ut_check(1 == test_result_monitor_move_constructor());
                bsl::ut_check(0 == test_result_monitor_copy_assignment());
                bsl::ut_check(0 == test_result_monitor_move_assignment());
                bsl::ut_check(test2.success());
            };
        };

        bsl::ut_check(2 == test_result_monitor_destructor());
    };

    bsl::ut_scenario{"move with errc"} = []() {
        bsl::ut_given{} = []() {
            result<test_result_monitor> test1{bsl::errc_failure};
            result<test_result_monitor> const test2{bsl::move(test1)};

            bsl::ut_then{} = [&test2]() {
                bsl::ut_check(0 == test_result_monitor_constructor());
                bsl::ut_check(0 == test_result_monitor_copy_constructor());
                bsl::ut_check(0 == test_result_monitor_move_constructor());
                bsl::ut_check(0 == test_result_monitor_copy_assignment());
                bsl::ut_check(0 == test_result_monitor_move_assignment());
                bsl::ut_check(test2.failure());
            };
        };

        bsl::ut_check(0 == test_result_monitor_destructor());
    };

    bsl::ut_scenario{"copy assignment with t"} = []() {
        bsl::ut_given{} = []() {
            result<test_result_monitor> const test1{bsl::in_place};
            result<test_result_monitor> test2{bsl::in_place};

            bsl::ut_when{} = [&test1, &test2]() {
                test2 = test1;

                bsl::ut_then{} = [&test1, &test2]() {
                    bsl::ut_check(2 == test_result_monitor_constructor());
                    bsl::ut_check(1 == test_result_monitor_copy_constructor());
                    bsl::ut_check(1 == test_result_monitor_move_constructor());
                    bsl::ut_check(0 == test_result_monitor_copy_assignment());
                    bsl::ut_check(2 == test_result_monitor_move_assignment());
                    bsl::ut_check(2 == test_result_monitor_destructor());
                    bsl::ut_check(test1.success());
                    bsl::ut_check(test2.success());
                };
            };
        };

        bsl::ut_check(2 == test_result_monitor_destructor());
    };

    bsl::ut_scenario{"move assignment with t"} = []() {
        bsl::ut_given{} = []() {
            result<test_result_monitor> test1{bsl::in_place};
            result<test_result_monitor> test2{bsl::in_place};

            bsl::ut_when{} = [&test1, &test2]() {
                test2 = bsl::move(test1);

                bsl::ut_then{} = [&test1, &test2]() {
                    bsl::ut_check(2 == test_result_monitor_constructor());
                    bsl::ut_check(0 == test_result_monitor_copy_constructor());
                    bsl::ut_check(2 == test_result_monitor_move_constructor());
                    bsl::ut_check(0 == test_result_monitor_copy_assignment());
                    bsl::ut_check(2 == test_result_monitor_move_assignment());
                    bsl::ut_check(2 == test_result_monitor_destructor());
                    bsl::ut_check(test1.success());
                    bsl::ut_check(test2.success());
                };
            };
        };

        bsl::ut_check(2 == test_result_monitor_destructor());
    };

    bsl::ut_scenario{"copy assignment with t/e"} = []() {
        bsl::ut_given{} = []() {
            result<test_result_monitor> const test1{bsl::in_place};
            result<test_result_monitor> test2{bsl::errc_failure};

            bsl::ut_when{} = [&test1, &test2]() {
                test2 = test1;

                bsl::ut_then{} = [&test1, &test2]() {
                    bsl::ut_check(1 == test_result_monitor_constructor());
                    bsl::ut_check(1 == test_result_monitor_copy_constructor());
                    bsl::ut_check(1 == test_result_monitor_move_constructor());
                    bsl::ut_check(0 == test_result_monitor_copy_assignment());
                    bsl::ut_check(0 == test_result_monitor_move_assignment());
                    bsl::ut_check(1 == test_result_monitor_destructor());
                    bsl::ut_check(test1.success());
                    bsl::ut_check(test2.success());
                };
            };
        };

        bsl::ut_check(2 == test_result_monitor_destructor());
    };

    bsl::ut_scenario{"copy assignment with e/t"} = []() {
        bsl::ut_given{} = []() {
            result<test_result_monitor> const test1{bsl::errc_failure};
            result<test_result_monitor> test2{bsl::in_place};

            bsl::ut_when{} = [&test1, &test2]() {
                test2 = test1;

                bsl::ut_then{} = [&test1, &test2]() {
                    bsl::ut_check(1 == test_result_monitor_constructor());
                    bsl::ut_check(0 == test_result_monitor_copy_constructor());
                    bsl::ut_check(1 == test_result_monitor_move_constructor());
                    bsl::ut_check(0 == test_result_monitor_copy_assignment());
                    bsl::ut_check(0 == test_result_monitor_move_assignment());
                    bsl::ut_check(2 == test_result_monitor_destructor());
                    bsl::ut_check(test1.failure());
                    bsl::ut_check(test2.failure());
                };
            };
        };

        bsl::ut_check(0 == test_result_monitor_destructor());
    };

    bsl::ut_scenario{"move assignment with t/e"} = []() {
        bsl::ut_given{} = []() {
            result<test_result_monitor> test1{bsl::in_place};
            result<test_result_monitor> test2{bsl::errc_failure};

            bsl::ut_when{} = [&test1, &test2]() {
                test2 = bsl::move(test1);

                bsl::ut_then{} = [&test1, &test2]() {
                    bsl::ut_check(1 == test_result_monitor_constructor());
                    bsl::ut_check(0 == test_result_monitor_copy_constructor());
                    bsl::ut_check(2 == test_result_monitor_move_constructor());
                    bsl::ut_check(0 == test_result_monitor_copy_assignment());
                    bsl::ut_check(0 == test_result_monitor_move_assignment());
                    bsl::ut_check(1 == test_result_monitor_destructor());
                    bsl::ut_check(test1.success());
                    bsl::ut_check(test2.success());
                };
            };
        };

        bsl::ut_check(2 == test_result_monitor_destructor());
    };

    bsl::ut_scenario{"move assignment with e/t"} = []() {
        bsl::ut_given{} = []() {
            result<test_result_monitor> test1{bsl::errc_failure};
            result<test_result_monitor> test2{bsl::in_place};

            bsl::ut_when{} = [&test1, &test2]() {
                test2 = bsl::move(test1);

                bsl::ut_then{} = [&test1, &test2]() {
                    bsl::ut_check(1 == test_result_monitor_constructor());
                    bsl::ut_check(0 == test_result_monitor_copy_constructor());
                    bsl::ut_check(1 == test_result_monitor_move_constructor());
                    bsl::ut_check(0 == test_result_monitor_copy_assignment());
                    bsl::ut_check(0 == test_result_monitor_move_assignment());
                    bsl::ut_check(2 == test_result_monitor_destructor());
                    bsl::ut_check(test1.failure());
                    bsl::ut_check(test2.failure());
                };
            };
        };

        bsl::ut_check(0 == test_result_monitor_destructor());
    };

    bsl::ut_scenario{"equality success"} = []() {
        bsl::ut_given{} = []() {
            result<bool> test1{bsl::in_place, true};
            result<bool> test2{bsl::in_place, true};

            bsl::ut_then{} = [&test1, &test2]() {
                bsl::ut_check(test1 == test2);
            };
        };
    };

    bsl::ut_scenario{"equality success and failure"} = []() {
        bsl::ut_given{} = []() {
            result<bool> test1{bsl::in_place, true};
            result<bool> test2{bsl::errc_failure};

            bsl::ut_then{} = [&test1, &test2]() {
                bsl::ut_check(test1 != test2);
            };
        };

        bsl::ut_given{} = []() {
            result<bool> test1{bsl::errc_failure};
            result<bool> test2{bsl::in_place, true};

            bsl::ut_then{} = [&test1, &test2]() {
                bsl::ut_check(test1 != test2);
            };
        };
    };

    bsl::ut_scenario{"equality failure"} = []() {
        bsl::ut_given{} = []() {
            result<bool> test1{bsl::errc_failure};
            result<bool> test2{bsl::errc_failure};

            bsl::ut_then{} = [&test1, &test2]() {
                bsl::ut_check(test1 == test2);
            };
        };
    };

    bsl::ut_scenario{"not equal"} = []() {
        bsl::ut_given{} = []() {
            result<bool> test1{bsl::in_place, true};
            result<bool> test2{bsl::in_place, false};

            bsl::ut_then{} = [&test1, &test2]() {
                bsl::ut_check(test1 != test2);
            };
        };

        bsl::ut_given{} = []() {
            result<bool> test1{bsl::errc_failure};
            result<bool> test2{bsl::errc_nullptr_dereference};

            bsl::ut_then{} = [&test1, &test2]() {
                bsl::ut_check(test1 != test2);
            };
        };
    };

    return bsl::ut_success();
}
