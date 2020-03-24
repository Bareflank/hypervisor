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

#include <bsl/delegate.hpp>
#include <bsl/ut.hpp>

namespace
{
    bool g_called{false};

    void
    reset_handler()
    {
        g_called = false;
    }

    [[nodiscard]] constexpr bool
    test_func(bool const val)
    {
        return val;
    }

    [[nodiscard]] constexpr bool
    test_func_noexcept(bool const val) noexcept
    {
        return val;
    }

    void
    test_func_void(bool const val)
    {
        bsl::discard(val);
        g_called = true;
    }

    void
    test_func_void_noexcept(bool const val) noexcept
    {
        bsl::discard(val);
        g_called = true;
    }

    class myclass final
    {
    public:
        [[nodiscard]] constexpr bool
        test_memfunc(bool const val)    // NOLINT
        {
            return val;
        }

        [[nodiscard]] constexpr bool
        test_memfunc_noexcept(bool const val) noexcept    // NOLINT
        {
            return val;
        }

        void
        test_memfunc_void(bool const val)    // NOLINT
        {
            bsl::discard(val);
            g_called = true;
        }

        void
        test_memfunc_void_noexcept(bool const val) noexcept    // NOLINT
        {
            bsl::discard(val);
            g_called = true;
        }

        [[nodiscard]] constexpr bool
        test_cmemfunc(bool const val) const    // NOLINT
        {
            return val;
        }

        [[nodiscard]] constexpr bool
        test_cmemfunc_noexcept(bool const val) const noexcept    // NOLINT
        {
            return val;
        }

        void
        test_cmemfunc_void(bool const val) const    // NOLINT
        {
            bsl::discard(val);
            g_called = true;
        }

        void
        test_cmemfunc_void_noexcept(bool const val) const noexcept    // NOLINT
        {
            bsl::discard(val);
            g_called = true;
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
    bsl::set_ut_reset_handler(&reset_handler);

    bsl::ut_scenario{"func"} = []() {
        bsl::ut_given{} = []() {
            bsl::delegate const func{&test_func};
            bsl::ut_when{} = [&func]() {
                ut_check(func.valid());
                auto const res{func(true)};
                bsl::ut_then{} = [&res]() {
                    bsl::ut_check(res.get_if() != nullptr);
                    bsl::ut_check(*res.get_if());
                };
            };

            static_assert(!noexcept(func(true)));
        };
    };

    bsl::ut_scenario{"func (noexcept)"} = []() {
        bsl::ut_given{} = []() {
            bsl::delegate const func{&test_func_noexcept};
            bsl::ut_when{} = [&func]() {
                ut_check(func.valid());
                auto const res{func(true)};
                bsl::ut_then{} = [&res]() {
                    bsl::ut_check(res.get_if() != nullptr);
                    bsl::ut_check(*res.get_if());
                };
            };

            static_assert(noexcept(func(true)));
        };
    };

    bsl::ut_scenario{"func with void return"} = []() {
        bsl::ut_given{} = []() {
            bsl::delegate const func{&test_func_void};
            bsl::ut_when{} = [&func]() {
                ut_check(func.valid());
                g_called = false;
                func(true);
                bsl::ut_then{} = []() {
                    bsl::ut_check(g_called);
                };
            };

            static_assert(!noexcept(func(true)));
        };
    };

    bsl::ut_scenario{"func with void return (noexcept)"} = []() {
        bsl::ut_given{} = []() {
            bsl::delegate const func{&test_func_void_noexcept};
            bsl::ut_when{} = [&func]() {
                ut_check(func.valid());
                g_called = false;
                func(true);
                bsl::ut_then{} = []() {
                    bsl::ut_check(g_called);
                };
            };

            static_assert(noexcept(func(true)));
        };
    };

    bsl::ut_scenario{"memfunc"} = []() {
        bsl::ut_given{} = []() {
            myclass c{};
            bsl::delegate const func{c, &myclass::test_memfunc};
            bsl::ut_when{} = [&func]() {
                ut_check(func.valid());
                auto const res{func(true)};
                bsl::ut_then{} = [&res]() {
                    bsl::ut_check(res.get_if() != nullptr);
                    bsl::ut_check(*res.get_if());
                };
            };

            static_assert(!noexcept(func(true)));
        };
    };

    bsl::ut_scenario{"memfunc (noexcept)"} = []() {
        bsl::ut_given{} = []() {
            myclass c{};
            bsl::delegate const func{c, &myclass::test_memfunc_noexcept};
            bsl::ut_when{} = [&func]() {
                ut_check(func.valid());
                auto const res{func(true)};
                bsl::ut_then{} = [&res]() {
                    bsl::ut_check(res.get_if() != nullptr);
                    bsl::ut_check(*res.get_if());
                };
            };

            static_assert(noexcept(func(true)));
        };
    };

    bsl::ut_scenario{"memfunc with void return"} = []() {
        bsl::ut_given{} = []() {
            myclass c{};
            bsl::delegate const func{c, &myclass::test_memfunc_void};
            bsl::ut_when{} = [&func]() {
                ut_check(func.valid());
                g_called = false;
                func(true);
                bsl::ut_then{} = []() {
                    bsl::ut_check(g_called);
                };
            };

            static_assert(!noexcept(func(true)));
        };
    };

    bsl::ut_scenario{"memfunc with void return (noexcept)"} = []() {
        bsl::ut_given{} = []() {
            myclass c{};
            bsl::delegate const func{c, &myclass::test_memfunc_void_noexcept};
            bsl::ut_when{} = [&func]() {
                ut_check(func.valid());
                g_called = false;
                func(true);
                bsl::ut_then{} = []() {
                    bsl::ut_check(g_called);
                };
            };

            static_assert(noexcept(func(true)));
        };
    };

    bsl::ut_scenario{"cmemfunc"} = []() {
        bsl::ut_given{} = []() {
            myclass c{};
            bsl::delegate const func{c, &myclass::test_cmemfunc};
            bsl::ut_when{} = [&func]() {
                ut_check(func.valid());
                auto const res{func(true)};
                bsl::ut_then{} = [&res]() {
                    bsl::ut_check(res.get_if() != nullptr);
                    bsl::ut_check(*res.get_if());
                };
            };

            static_assert(!noexcept(func(true)));
        };
    };

    bsl::ut_scenario{"cmemfunc (noexcept)"} = []() {
        bsl::ut_given{} = []() {
            myclass c{};
            bsl::delegate const func{c, &myclass::test_cmemfunc_noexcept};
            bsl::ut_when{} = [&func]() {
                ut_check(func.valid());
                auto const res{func(true)};
                bsl::ut_then{} = [&res]() {
                    bsl::ut_check(res.get_if() != nullptr);
                    bsl::ut_check(*res.get_if());
                };
            };

            static_assert(noexcept(func(true)));
        };
    };

    bsl::ut_scenario{"cmemfunc with void return"} = []() {
        bsl::ut_given{} = []() {
            myclass c{};
            bsl::delegate const func{c, &myclass::test_cmemfunc_void};
            bsl::ut_when{} = [&func]() {
                ut_check(func.valid());
                g_called = false;
                func(true);
                bsl::ut_then{} = []() {
                    bsl::ut_check(g_called);
                };
            };

            static_assert(!noexcept(func(true)));
        };
    };

    bsl::ut_scenario{"cmemfunc with void return (noexcept)"} = []() {
        bsl::ut_given{} = []() {
            myclass c{};
            bsl::delegate const func{c, &myclass::test_cmemfunc_void_noexcept};
            bsl::ut_when{} = [&func]() {
                ut_check(func.valid());
                g_called = false;
                func(true);
                bsl::ut_then{} = []() {
                    bsl::ut_check(g_called);
                };
            };

            static_assert(noexcept(func(true)));
        };
    };

    bsl::ut_scenario{"default constructor with no signature"} = []() {
        bsl::ut_given{} = []() {
            bsl::delegate const func{};
            bsl::ut_then{} = [&func]() {
                bsl::ut_check(!func.valid());
                func();
            };

            static_assert(noexcept(func()));
        };
    };

    bsl::ut_scenario{"default constructor"} = []() {
        bsl::ut_given{} = []() {
            bsl::delegate<bool()> const func{};
            bsl::ut_then{} = [&func]() {
                bsl::ut_check(!func.valid());
                bsl::ut_check(!func().success());
            };

            static_assert(!noexcept(func()));
        };
    };

    bsl::ut_scenario{"default constructor with void return"} = []() {
        bsl::ut_given{} = []() {
            bsl::delegate<void()> const func{};
            bsl::ut_then{} = [&func]() {
                bsl::ut_check(!func.valid());
                func();
            };

            static_assert(!noexcept(func()));
        };
    };

    bsl::ut_scenario{"default constructor (noexcept)"} = []() {
        bsl::ut_given{} = []() {
            bsl::delegate<bool() noexcept> const func{};
            bsl::ut_then{} = [&func]() {
                bsl::ut_check(!func.valid());
                bsl::ut_check(!func().success());
            };

            static_assert(noexcept(func()));
        };
    };

    bsl::ut_scenario{"default constructor with void return (noexcept)"} = []() {
        bsl::ut_given{} = []() {
            bsl::delegate<void() noexcept> const func{};
            bsl::ut_then{} = [&func]() {
                bsl::ut_check(!func.valid());
                func();
            };

            static_assert(noexcept(func()));
        };
    };

    bsl::ut_scenario{"nullptr func"} = []() {
        bsl::ut_given{} = []() {
            bool (*myfunc)(bool){};
            bsl::delegate const func{myfunc};
            bsl::ut_when{} = [&func]() {
                ut_check(!func.valid());
                auto const res{func(true)};
                bsl::ut_then{} = [&res]() {
                    bsl::ut_check(res.get_if() == nullptr);
                };
            };

            static_assert(!noexcept(func(true)));
        };
    };

    bsl::ut_scenario{"nullptr func (noexcept)"} = []() {
        bsl::ut_given{} = []() {
            bool (*myfunc)(bool) noexcept {};
            bsl::delegate const func{myfunc};
            bsl::ut_when{} = [&func]() {
                ut_check(!func.valid());
                auto const res{func(true)};
                bsl::ut_then{} = [&res]() {
                    bsl::ut_check(res.get_if() == nullptr);
                };
            };

            static_assert(noexcept(func(true)));
        };
    };

    bsl::ut_scenario{"nullptr func with void return"} = []() {
        bsl::ut_given{} = []() {
            void (*myfunc)(bool){};
            bsl::delegate const func{myfunc};
            bsl::ut_when{} = [&func]() {
                ut_check(!func.valid());
                func(true);
            };

            static_assert(!noexcept(func(true)));
        };
    };

    bsl::ut_scenario{"nullptr func with void return (noexcept)"} = []() {
        bsl::ut_given{} = []() {
            void (*myfunc)(bool) noexcept {};
            bsl::delegate const func{myfunc};
            bsl::ut_when{} = [&func]() {
                ut_check(!func.valid());
                func(true);
            };

            static_assert(noexcept(func(true)));
        };
    };

    bsl::ut_scenario{"nullptr memfunc"} = []() {
        bsl::ut_given{} = []() {
            myclass c{};
            bool (myclass::*myfunc)(bool){};
            bsl::delegate const func{c, myfunc};
            bsl::ut_when{} = [&func]() {
                ut_check(!func.valid());
                auto const res{func(true)};
                bsl::ut_then{} = [&res]() {
                    bsl::ut_check(res.get_if() == nullptr);
                };
            };

            static_assert(!noexcept(func(true)));
        };
    };

    bsl::ut_scenario{"nullptr memfunc (noexcept)"} = []() {
        bsl::ut_given{} = []() {
            myclass c{};
            bool (myclass::*myfunc)(bool) noexcept {};
            bsl::delegate const func{c, myfunc};
            bsl::ut_when{} = [&func]() {
                ut_check(!func.valid());
                auto const res{func(true)};
                bsl::ut_then{} = [&res]() {
                    bsl::ut_check(res.get_if() == nullptr);
                };
            };

            static_assert(noexcept(func(true)));
        };
    };

    bsl::ut_scenario{"nullptr memfunc with void return"} = []() {
        bsl::ut_given{} = []() {
            myclass c{};
            void (myclass::*myfunc)(bool){};
            bsl::delegate const func{c, myfunc};
            bsl::ut_when{} = [&func]() {
                ut_check(!func.valid());
                func(true);
            };

            static_assert(!noexcept(func(true)));
        };
    };

    bsl::ut_scenario{"nullptr memfunc with void return (noexcept)"} = []() {
        bsl::ut_given{} = []() {
            myclass c{};
            void (myclass::*myfunc)(bool) noexcept {};
            bsl::delegate const func{c, myfunc};
            bsl::ut_when{} = [&func]() {
                ut_check(!func.valid());
                func(true);
            };

            static_assert(noexcept(func(true)));
        };
    };

    bsl::ut_scenario{"nullptr cmemfunc"} = []() {
        bsl::ut_given{} = []() {
            myclass c{};
            bool (myclass::*myfunc)(bool) const {};
            bsl::delegate const func{c, myfunc};
            bsl::ut_when{} = [&func]() {
                ut_check(!func.valid());
                auto const res{func(true)};
                bsl::ut_then{} = [&res]() {
                    bsl::ut_check(res.get_if() == nullptr);
                };
            };

            static_assert(!noexcept(func(true)));
        };
    };

    bsl::ut_scenario{"nullptr cmemfunc (noexcept)"} = []() {
        bsl::ut_given{} = []() {
            myclass c{};
            bool (myclass::*myfunc)(bool) const noexcept {};
            bsl::delegate const func{c, myfunc};
            bsl::ut_when{} = [&func]() {
                ut_check(!func.valid());
                auto const res{func(true)};
                bsl::ut_then{} = [&res]() {
                    bsl::ut_check(res.get_if() == nullptr);
                };
            };

            static_assert(noexcept(func(true)));
        };
    };

    bsl::ut_scenario{"nullptr cmemfunc with void return"} = []() {
        bsl::ut_given{} = []() {
            myclass c{};
            void (myclass::*myfunc)(bool) const {};
            bsl::delegate const func{c, myfunc};
            bsl::ut_when{} = [&func]() {
                ut_check(!func.valid());
                func(true);
            };

            static_assert(!noexcept(func(true)));
        };
    };

    bsl::ut_scenario{"nullptr cmemfunc with void return (noexcept)"} = []() {
        bsl::ut_given{} = []() {
            myclass c{};
            void (myclass::*myfunc)(bool) const noexcept {};
            bsl::delegate const func{c, myfunc};
            bsl::ut_when{} = [&func]() {
                ut_check(!func.valid());
                func(true);
            };

            static_assert(noexcept(func(true)));
        };
    };

    bsl::ut_scenario{"copy construction"} = []() {
        bsl::ut_given{} = []() {
            bsl::delegate const func1{&test_func};
            bsl::delegate const func2{func1};
            bsl::ut_when{} = [&func2]() {
                auto const res{func2(true)};
                bsl::ut_then{} = [&res]() {
                    bsl::ut_check(res.get_if() != nullptr);
                    bsl::ut_check(*res.get_if());
                };
            };
        };
    };

    bsl::ut_scenario{"copy construction (noexcept)"} = []() {
        bsl::ut_given{} = []() {
            bsl::delegate const func1{&test_func_noexcept};
            bsl::delegate const func2{func1};
            bsl::ut_when{} = [&func2]() {
                auto const res{func2(true)};
                bsl::ut_then{} = [&res]() {
                    bsl::ut_check(res.get_if() != nullptr);
                    bsl::ut_check(*res.get_if());
                };
            };
        };
    };

    bsl::ut_scenario{"copy construction with void return"} = []() {
        bsl::ut_given{} = []() {
            bsl::delegate const func1{&test_func_void};
            bsl::delegate const func2{func1};
            bsl::ut_when{} = [&func2]() {
                ut_check(func2.valid());
                g_called = false;
                func2(true);
                bsl::ut_then{} = []() {
                    bsl::ut_check(g_called);
                };
            };
        };
    };

    bsl::ut_scenario{"copy construction with void return"} = []() {
        bsl::ut_given{} = []() {
            bsl::delegate const func1{&test_func_void_noexcept};
            bsl::delegate const func2{func1};
            bsl::ut_when{} = [&func2]() {
                ut_check(func2.valid());
                g_called = false;
                func2(true);
                bsl::ut_then{} = []() {
                    bsl::ut_check(g_called);
                };
            };
        };
    };

    bsl::ut_scenario{"move construction"} = []() {
        bsl::ut_given{} = []() {
            bsl::delegate func1{&test_func};
            bsl::delegate const func2{bsl::move(func1)};
            bsl::ut_when{} = [&func2]() {
                auto const res{func2(true)};
                bsl::ut_then{} = [&res]() {
                    bsl::ut_check(res.get_if() != nullptr);
                    bsl::ut_check(*res.get_if());
                };
            };
        };
    };

    bsl::ut_scenario{"move construction (noexcept)"} = []() {
        bsl::ut_given{} = []() {
            bsl::delegate func1{&test_func_noexcept};
            bsl::delegate const func2{bsl::move(func1)};
            bsl::ut_when{} = [&func2]() {
                auto const res{func2(true)};
                bsl::ut_then{} = [&res]() {
                    bsl::ut_check(res.get_if() != nullptr);
                    bsl::ut_check(*res.get_if());
                };
            };
        };
    };

    bsl::ut_scenario{"move construction with void return"} = []() {
        bsl::ut_given{} = []() {
            bsl::delegate func1{&test_func_void};
            bsl::delegate const func2{bsl::move(func1)};
            bsl::ut_when{} = [&func2]() {
                ut_check(func2.valid());
                g_called = false;
                func2(true);
                bsl::ut_then{} = []() {
                    bsl::ut_check(g_called);
                };
            };
        };
    };

    bsl::ut_scenario{"move construction with void return"} = []() {
        bsl::ut_given{} = []() {
            bsl::delegate func1{&test_func_void_noexcept};
            bsl::delegate const func2{bsl::move(func1)};
            bsl::ut_when{} = [&func2]() {
                ut_check(func2.valid());
                g_called = false;
                func2(true);
                bsl::ut_then{} = []() {
                    bsl::ut_check(g_called);
                };
            };
        };
    };

    bsl::ut_scenario{"copy assignment"} = []() {
        bsl::ut_given{} = []() {
            bsl::delegate const func1{&test_func};
            bsl::delegate<bool(bool)> func2{};
            bsl::ut_when{} = [&func1, &func2]() {
                func2 = func1;
                auto const res{func2(true)};
                bsl::ut_then{} = [&res]() {
                    bsl::ut_check(res.get_if() != nullptr);
                    bsl::ut_check(*res.get_if());
                };
            };
        };
    };

    bsl::ut_scenario{"copy assignment (noexcept)"} = []() {
        bsl::ut_given{} = []() {
            bsl::delegate const func1{&test_func_noexcept};
            bsl::delegate<bool(bool) noexcept> func2{};
            bsl::ut_when{} = [&func1, &func2]() {
                func2 = func1;
                ut_check(func2.valid());
                auto const res{func2(true)};
                bsl::ut_then{} = [&res]() {
                    bsl::ut_check(res.get_if() != nullptr);
                    bsl::ut_check(*res.get_if());
                };
            };
        };
    };

    bsl::ut_scenario{"copy assignment with void return"} = []() {
        bsl::ut_given{} = []() {
            bsl::delegate const func1{&test_func_void};
            bsl::delegate<void(bool)> func2{};
            bsl::ut_when{} = [&func1, &func2]() {
                func2 = func1;
                ut_check(func2.valid());
                g_called = false;
                func2(true);
                bsl::ut_then{} = []() {
                    bsl::ut_check(g_called);
                };
            };
        };
    };

    bsl::ut_scenario{"copy assignment with void return (noexcept)"} = []() {
        bsl::ut_given{} = []() {
            bsl::delegate const func1{&test_func_void_noexcept};
            bsl::delegate<void(bool) noexcept> func2{};
            bsl::ut_when{} = [&func1, &func2]() {
                func2 = func1;
                ut_check(func2.valid());
                g_called = false;
                func2(true);
                bsl::ut_then{} = []() {
                    bsl::ut_check(g_called);
                };
            };
        };
    };

    bsl::ut_scenario{"move assignment"} = []() {
        bsl::ut_given{} = []() {
            bsl::delegate func1{&test_func};
            bsl::delegate<bool(bool)> func2{};
            bsl::ut_when{} = [&func1, &func2]() {
                func2 = bsl::move(func1);
                auto const res{func2(true)};
                bsl::ut_then{} = [&res]() {
                    bsl::ut_check(res.get_if() != nullptr);
                    bsl::ut_check(*res.get_if());
                };
            };
        };
    };

    bsl::ut_scenario{"move assignment (noexcept)"} = []() {
        bsl::ut_given{} = []() {
            bsl::delegate func1{&test_func_noexcept};
            bsl::delegate<bool(bool) noexcept> func2{};
            bsl::ut_when{} = [&func1, &func2]() {
                func2 = bsl::move(func1);
                ut_check(func2.valid());
                auto const res{func2(true)};
                bsl::ut_then{} = [&res]() {
                    bsl::ut_check(res.get_if() != nullptr);
                    bsl::ut_check(*res.get_if());
                };
            };
        };
    };

    bsl::ut_scenario{"move assignment with void return"} = []() {
        bsl::ut_given{} = []() {
            bsl::delegate func1{&test_func_void};
            bsl::delegate<void(bool)> func2{};
            bsl::ut_when{} = [&func1, &func2]() {
                func2 = bsl::move(func1);
                ut_check(func2.valid());
                g_called = false;
                func2(true);
                bsl::ut_then{} = []() {
                    bsl::ut_check(g_called);
                };
            };
        };
    };

    bsl::ut_scenario{"move assignment with void return (noexcept)"} = []() {
        bsl::ut_given{} = []() {
            bsl::delegate func1{&test_func_void_noexcept};
            bsl::delegate<void(bool) noexcept> func2{};
            bsl::ut_when{} = [&func1, &func2]() {
                func2 = bsl::move(func1);
                ut_check(func2.valid());
                g_called = false;
                func2(true);
                bsl::ut_then{} = []() {
                    bsl::ut_check(g_called);
                };
            };
        };
    };

    return bsl::ut_success();
}
