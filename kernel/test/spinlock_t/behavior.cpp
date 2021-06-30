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

#include "../../src/spinlock_t.hpp"

#include <atomic>
#include <thread>
#include <tls_t.hpp>

#include <bsl/array.hpp>
#include <bsl/ut.hpp>

namespace mk
{
    /// @brief defines the max number of wait threads
    constexpr auto MAX_WAIT_THREADS{1024_umax};
    /// @brief defines the global spin lock used for the thread tests
    constinit spinlock_t g_spinlock{};
    /// @brief defines the dummy TLS block for the block thread
    constinit tls_t g_tls_block{};
    /// @brief defines the dummy TLS block for wait thread
    constinit bsl::array<tls_t, MAX_WAIT_THREADS.get()> g_tls_wait{};
    /// @brief stores how many threads are started
    constinit std::atomic<bsl::uint64> g_threads_started{};
    /// @brief stores how many threads had to wait
    constinit std::atomic<bsl::uint64> g_threads_that_waited{};

    /// <!-- description -->
    ///   @brief Implements a yield for the spinlock
    ///
    extern "C" void
    yield() noexcept
    {
        std::this_thread::yield();
    }

    /// <!-- description -->
    ///   @brief Used to test to make sure that threads have to wait
    ///
    void
    thread_func(bsl::safe_uintmax const ppid)
    {
        bool this_thread_waited{};

        auto *const tls{g_tls_wait.at_if(ppid)};
        tls->ppid = bsl::to_u16(ppid).get();

        ++g_threads_started;

        g_spinlock.lock(*tls);
        while (static_cast<bsl::uint64>(g_threads_started) < MAX_WAIT_THREADS) {
            if (!this_thread_waited) {
                ++g_threads_that_waited;
                this_thread_waited = true;
            }

            yield();
        }
        g_spinlock.unlock(*tls);
    }

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
        bsl::ut_scenario{"lock/unlock"} = []() {
            bsl::ut_given_at_runtime{} = []() {
                spinlock_t spinlock{};
                tls_t tls{};
                bsl::ut_when{} = [&spinlock, &tls]() {
                    tls.esr_ip = {};
                    spinlock.lock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(spinlock.is_locked());
                    };

                    tls.esr_ip = {};
                    spinlock.unlock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(!spinlock.is_locked());
                    };
                };
            };
        };

        bsl::ut_scenario{"lock/unlock from esr"} = []() {
            bsl::ut_given_at_runtime{} = []() {
                spinlock_t spinlock{};
                tls_t tls{};
                bsl::ut_when{} = [&spinlock, &tls]() {
                    tls.esr_ip = (1_umax).get();
                    spinlock.lock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(spinlock.is_locked());
                    };

                    tls.esr_ip = (1_umax).get();
                    spinlock.unlock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(!spinlock.is_locked());
                    };
                };
            };
        };

        bsl::ut_scenario{"lock twice"} = []() {
            bsl::ut_given_at_runtime{} = []() {
                spinlock_t spinlock{};
                tls_t tls{};
                bsl::ut_when{} = [&spinlock, &tls]() {
                    tls.esr_ip = {};
                    spinlock.lock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(spinlock.is_locked());
                    };

                    tls.esr_ip = {};
                    spinlock.lock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(spinlock.is_locked());
                    };

                    tls.esr_ip = {};
                    spinlock.unlock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(!spinlock.is_locked());
                    };
                };
            };
        };

        bsl::ut_scenario{"lock twice from esr"} = []() {
            bsl::ut_given_at_runtime{} = []() {
                spinlock_t spinlock{};
                tls_t tls{};
                bsl::ut_when{} = [&spinlock, &tls]() {
                    tls.esr_ip = (1_umax).get();
                    spinlock.lock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(spinlock.is_locked());
                    };

                    tls.esr_ip = (1_umax).get();
                    spinlock.lock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(spinlock.is_locked());
                    };

                    tls.esr_ip = (1_umax).get();
                    spinlock.unlock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(!spinlock.is_locked());
                    };
                };
            };
        };

        bsl::ut_scenario{"lock std, lock esr, unlock esr, unlock std"} = []() {
            bsl::ut_given_at_runtime{} = []() {
                spinlock_t spinlock{};
                tls_t tls{};
                bsl::ut_when{} = [&spinlock, &tls]() {
                    tls.esr_ip = {};
                    spinlock.lock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(spinlock.is_locked());
                    };

                    tls.esr_ip = (1_umax).get();
                    spinlock.lock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(spinlock.is_locked());
                    };

                    tls.esr_ip = (1_umax).get();
                    spinlock.unlock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(spinlock.is_locked());
                    };

                    tls.esr_ip = {};
                    spinlock.unlock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(!spinlock.is_locked());
                    };
                };
            };
        };

        bsl::ut_scenario{"lock esr, lock std, unlock std, unlock esr"} = []() {
            bsl::ut_given_at_runtime{} = []() {
                spinlock_t spinlock{};
                tls_t tls{};
                bsl::ut_when{} = [&spinlock, &tls]() {
                    tls.esr_ip = (1_umax).get();
                    spinlock.lock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(spinlock.is_locked());
                    };

                    tls.esr_ip = {};
                    spinlock.lock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(spinlock.is_locked());
                    };

                    tls.esr_ip = {};
                    spinlock.unlock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(spinlock.is_locked());
                    };

                    tls.esr_ip = (1_umax).get();
                    spinlock.unlock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(!spinlock.is_locked());
                    };
                };
            };
        };

        bsl::ut_scenario{"lock esr, lock std, unlock esr, unlock std"} = []() {
            bsl::ut_given_at_runtime{} = []() {
                spinlock_t spinlock{};
                tls_t tls{};
                bsl::ut_when{} = [&spinlock, &tls]() {
                    tls.esr_ip = (1_umax).get();
                    spinlock.lock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(spinlock.is_locked());
                    };

                    tls.esr_ip = {};
                    spinlock.lock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(spinlock.is_locked());
                    };

                    tls.esr_ip = (1_umax).get();
                    spinlock.unlock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(spinlock.is_locked());
                    };

                    tls.esr_ip = {};
                    spinlock.unlock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(!spinlock.is_locked());
                    };
                };
            };
        };

        bsl::ut_scenario{"lock std, lock esr, unlock std, unlock esr"} = []() {
            bsl::ut_given_at_runtime{} = []() {
                spinlock_t spinlock{};
                tls_t tls{};
                bsl::ut_when{} = [&spinlock, &tls]() {
                    tls.esr_ip = {};
                    spinlock.lock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(spinlock.is_locked());
                    };

                    tls.esr_ip = (1_umax).get();
                    spinlock.lock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(spinlock.is_locked());
                    };

                    tls.esr_ip = {};
                    spinlock.unlock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(spinlock.is_locked());
                    };

                    tls.esr_ip = (1_umax).get();
                    spinlock.unlock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(!spinlock.is_locked());
                    };
                };
            };
        };

        bsl::ut_scenario{"lock std, lock esr, lock esr,  unlock std, unlock esr"} = []() {
            bsl::ut_given_at_runtime{} = []() {
                spinlock_t spinlock{};
                tls_t tls{};
                bsl::ut_when{} = [&spinlock, &tls]() {
                    tls.esr_ip = {};
                    spinlock.lock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(spinlock.is_locked());
                    };

                    tls.esr_ip = (1_umax).get();
                    spinlock.lock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(spinlock.is_locked());
                    };

                    tls.esr_ip = (1_umax).get();
                    spinlock.lock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(spinlock.is_locked());
                    };

                    tls.esr_ip = {};
                    spinlock.unlock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(spinlock.is_locked());
                    };

                    tls.esr_ip = (1_umax).get();
                    spinlock.unlock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(!spinlock.is_locked());
                    };
                };
            };
        };

        bsl::ut_scenario{"lock esr, lock std, lock std, unlock esr, unlock std"} = []() {
            bsl::ut_given_at_runtime{} = []() {
                spinlock_t spinlock{};
                tls_t tls{};
                bsl::ut_when{} = [&spinlock, &tls]() {
                    tls.esr_ip = (1_umax).get();
                    spinlock.lock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(spinlock.is_locked());
                    };

                    tls.esr_ip = {};
                    spinlock.lock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(spinlock.is_locked());
                    };

                    tls.esr_ip = {};
                    spinlock.lock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(spinlock.is_locked());
                    };

                    tls.esr_ip = (1_umax).get();
                    spinlock.unlock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(spinlock.is_locked());
                    };

                    tls.esr_ip = {};
                    spinlock.unlock(tls);
                    bsl::ut_then{} = [&spinlock]() {
                        bsl::ut_check(!spinlock.is_locked());
                    };
                };
            };
        };

        bsl::ut_scenario{"prove spin locks wait"} = []() {
            bsl::ut_given_at_runtime{} = []() {
                bsl::array<std::thread, MAX_WAIT_THREADS.get()> threads{};
                bsl::ut_when{} = [&threads]() {
                    for (bsl::safe_uintmax i{}; i < MAX_WAIT_THREADS; ++i) {
                        *threads.at_if(i) = std::thread{&thread_func, i};
                    }
                    for (bsl::safe_uintmax i{}; i < MAX_WAIT_THREADS; ++i) {
                        threads.at_if(i)->join();
                    }
                    bsl::ut_then{} = []() {
                        bsl::ut_check(
                            static_cast<bsl::uint64>(g_threads_started) == MAX_WAIT_THREADS);

                        // NOTE:
                        // - If g_threads_that_waited is one, it means that
                        //   all of the threads were locked until they were
                        //   all started. Once there are all started, the
                        //   thread that gets the critical region first will
                        //   be the only thread that had to wait. The rest
                        //   will get access to the critical region and just
                        //   pass through. This proves that some of the threads
                        //   had to spin on the spinlock and not pass through,
                        //   otherwise this count would be higher than 1.
                        // - What is great about this approach is that it will
                        //   work no matter how many threads you create, and
                        //   it will also work on single core systems. It also
                        //   ensures that every line and break is executed, so
                        //   there are no race conditions, which previous
                        //   attempts at this test had.
                        //

                        bsl::ut_check(static_cast<bsl::uint64>(g_threads_that_waited) == 1_umax);
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
    mk::yield();

    static_assert(mk::tests() == bsl::ut_success());
    return mk::tests();
}
