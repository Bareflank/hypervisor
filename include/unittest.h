//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#ifndef UNITTEST_H
#define UNITTEST_H

#ifdef OS_LINUX
#define LINUX_TARGET
#endif

#include <stdlib.h>
#include <iostream>
#include <exception.h>
#include <gsl/gsl>

#define NO_HIPPOMOCKS_NAMESPACE

#pragma GCC system_header
#include <hippomocks.h>

// A simple structure for encapsulating relevant exception expectations
struct exception_state
{
    bool caught;
    bool wrong_exception;
    std::string caught_str;
    std::string expecting_str;
};

/// Expect True
///
/// This macro verifies a unit test to be true. If the unit test is not
/// true, the unit test reports a failue and continues testing.
///
/// @code
///
/// EXPECT_TRUE(1 == 0) // unit test fails
/// EXPECT_TRUE(1 == 1) // unit test passes
///
/// @endcode
///
#define EXPECT_TRUE(condition) \
    if((condition)) { this->inc_pass(); } \
    else { this->expect_failed(#condition, static_cast<const char *>(__PRETTY_FUNCTION__), __LINE__); }

/// Expect True
///
/// This macro passes the boolean condition c along with the caller's name and line information
/// to expect_true_with_args. This macro must be invoked on the unittest object using this.
///
/// @code
///
/// this->expect_true(1 == 0) // unit test fails
/// this->expect_true(1 == 1) // unit test passes
///
/// @endcode
///
#define expect_true(c) expect_true_with_args(c, gsl::cstring_span<>(#c), gsl::cstring_span<>(__PRETTY_FUNCTION__), __LINE__)

/// Expect False
///
/// This macro verifies a unit test to be false. If the unit test is not
/// false, the unit test reports a failue and continues testing.
///
/// @code
///
/// EXPECT_FALSE(1 == 1) // unit test fails
/// EXPECT_FALSE(1 == 0) // unit test passes
///
/// @endcode
///
#define EXPECT_FALSE(condition) \
    if(!(condition)) { this->inc_pass(); } \
    else { this->expect_failed(#condition, static_cast<const char *>(__PRETTY_FUNCTION__), __LINE__); }

/// Expect False
///
/// This macro passes the boolean condition c along with the caller's name and line information
/// to expect_false_with_args. This macro must be invoked on the unittest object using this.
///
/// @code
///
/// this->expect_false(1 == 0) // unit test passes
/// this->expect_false(1 == 1) // unit test fails
///
/// @endcode
///
#define expect_false(c) expect_false_with_args(c, gsl::cstring_span<>(#c), gsl::cstring_span<>(__PRETTY_FUNCTION__), __LINE__)

/// Expect Exception
///
/// This macro verifies a unit test throws an exception. If the unit
/// test throws an exception, the unit test reports a failue and continues
/// testing.
///
/// @code
///
/// EXPECT_EXCEPTION(blah.do_something(), std::exception) // unit test fails if no throw()
///
/// @endcode
///
#define EXPECT_EXCEPTION(a, b) \
    { \
        bool caught = false; \
        bool wrong_exception = false; \
        std::string caught_str; \
        std::string expecting_str; \
        try{ a; } \
        catch(BaseException &be) \
        { \
            throw; \
        } \
        catch(bfn::general_exception &ge) \
        { \
            caught = true; \
            if (strcmp(typeid(ge).name(), typeid(b).name()) != 0) \
            { \
                wrong_exception = true; \
                caught_str = typeid(ge).name(); \
                expecting_str = typeid(b).name(); \
            } \
            else \
                std::cout << "caught: " << ge << '\n'; \
        } \
        catch(std::exception &e) \
        { \
            caught = true; \
            if (strcmp(typeid(e).name(), typeid(b).name()) != 0) \
            { \
                wrong_exception = true; \
                caught_str = typeid(e).name(); \
                expecting_str = typeid(b).name(); \
            } \
            else \
                std::cout << "caught: " << e << '\n'; \
        } \
        catch(...) \
        { \
            caught = true; \
            wrong_exception = true; \
            std::cerr << "unknown exception caught" << '\n'; \
        } \
        if(!caught) \
        { \
            this->expect_failed("no exception was caught", static_cast<const char *>(__PRETTY_FUNCTION__), __LINE__); \
        } \
        else \
        { \
            if (wrong_exception) \
            { \
                this->expect_failed("wrong exception caught", static_cast<const char *>(__PRETTY_FUNCTION__), __LINE__); \
                std::cerr << "    - caught: " << caught_str << '\n'; \
                std::cerr << "    - expecting: " << expecting_str << '\n'; \
            } \
            else \
                this->inc_pass(); \
        } \
    }

/// Expect Exception
///
/// This macro is used to pass the function name and line number to
/// expect_exception_with_args. The argument f is a function that
/// takes no arguments and returns void. The argument e is a
/// std::shared_ptr<std::exception> whose dynamic type is the same
/// as the exception in the throw statement in function-under-test.
///
/// If the caller wishes to pass a function that takes arguments
/// they must first std::bind the arguments (with appropriate forwarding as
/// needed), and pass the result of the bind to expect_exception_with_args.
///
/// @code
///
/// void g(int, double) { throw std::logic_error("error"); };
///
/// class Foo {
/// public:
///     void bar(int a, int b)
///     {
///         b = b + a;
///         throw std::runtime_error("addition error");
///     }
/// };
///
/// int arg1 = 0;
/// double arg2 = 1.0;
/// Foo foo;
///
/// auto f1 = std::bind(&Foo::bar, &foo, arg1, arg1);
/// auto f2 = std::bind(g, arg1, arg2);
///
/// auto e1 = std::shared_ptr<std::exception>(new std::runtime_error("addition error"));
/// auto e2 = std::shared_ptr<std::exception>(new std::logic_error("error"));
///
/// // unit test succeeds since foo.bar(arg1, arg1) throws runtime_error
/// this->expect_exception(f1, e1);
///
/// // unit test fails since runtime_error != logic_error
/// this->expect_exception(f1, e2);
///
/// // unit test succeeds since g(arg1, arg2) throws logic error
/// this->expect_exception(f2, e2);
///
/// @endcode
///
#define expect_exception(f, e) expect_exception_with_args(f, e, __PRETTY_FUNCTION__, __LINE__)


/// Expect No Exception
///
/// This macro verifies a unit test does not throw an exception. If the unit
/// test does not throw an exception, the unit test reports a failue and
/// continues testing.
///
/// @code
///
/// EXPECT_NO_EXCEPTION(blah.do_something()) // unit test fails if throw()
///
/// @endcode
///
#define EXPECT_NO_EXCEPTION(a) \
    { \
        bool caught = false; \
        try{ a; } \
        catch(BaseException &be) { throw; } \
        catch(bfn::general_exception &ge) { caught = true; } \
        catch(std::exception &e) { caught = true; } \
        catch(...) { caught = true; } \
        EXPECT_FALSE(caught); \
    }

/// Expect No Exception
///
/// This macro is used to pass the function name and line number to
/// expect_no_exception_with_args. The argument f is
/// a function that takes no arguments and returns void.
///
/// If the caller wishes to pass a function that takes arguments
/// they must first std::bind the arguments (with appropriate forwarding as
/// needed), and pass the result of the bind to expect_no_exception_with_args.
///
/// @code
///
/// void g(int, double);
///
/// class Foo {
/// public:
///     void bar(int, double);
/// };
///
/// int arg1 = 0;
/// double arg2 = 1.0;
/// Foo foo;
///
/// auto f1 = std::bind(&Foo::bar, &foo, arg1, arg2);
/// auto f2 = std::bind(g, arg1, arg2);
///
/// // unit test fails if foo.bar(arg1, arg2) throws
/// this->expect_no_exception(f1);
///
/// // unit test fails if g(arg1, arg2) throws
/// this->expect_no_exception(f2);
///
/// @endcode
///
#define expect_no_exception(f) expect_no_exception_with_args(f, __PRETTY_FUNCTION__, __LINE__)

/// Assert True
///
/// This macro verifies a unit test to be true. If the unit test is not
/// true, the unit test reports a failue and stops.
///
/// @code
///
/// ASSERT_TRUE(1 == 0) // unit test fails
/// ASSERT_TRUE(1 == 1) // unit test is not executed, but would have passed
///
/// @endcode
///
#define ASSERT_TRUE(condition) \
    if((condition)) { this->inc_pass(); } \
    else { this->assert_failed(#condition, static_cast<const char *>(__PRETTY_FUNCTION__), __LINE__); }

/// Assert False
///
/// This macro verifies a unit test to be false. If the unit test is not
/// false, the unit test reports a failue and stops.
///
/// @code
///
/// ASSERT_FALSE(1 == 1) // unit test fails
/// ASSERT_FALSE(1 == 0) // unit test is not executed, but would have passed
///
/// @endcode
///
#define ASSERT_FALSE(condition) \
    if(!(condition)) { this->inc_pass(); } \
    else { this->assert_failed(#condition, static_cast<const char *>(__PRETTY_FUNCTION__), __LINE__); }

/// Assert Exception
///
/// This macro verifies a unit test throws an exception. If the unit
/// test does not throw an exception, the unit test reports a failue and stops.
///
/// @code
///
/// ASSERT_EXCEPTION(blah.do_something(), std::exception) // unit test fails if throw()
///
/// @endcode
///

#define ASSERT_EXCEPTION(a, b) \
    { \
        bool caught = false; \
        bool wrong_exception = false; \
        std::string caught_str; \
        std::string expecting_str; \
        try{ a; } \
        catch(BaseException &be) \
        { \
            throw; \
        } \
        catch(bfn::general_exception &ge) \
        { \
            caught = true; \
            if (strcmp(typeid(ge).name(), typeid(b).name()) != 0) \
            { \
                wrong_exception = true; \
                caught_str = typeid(ge).name(); \
                expecting_str = typeid(b).name(); \
            } \
            else \
                std::cout << "caught: " << ge << '\n'; \
        } \
        catch(std::exception &e) \
        { \
            caught = true; \
            if (strcmp(typeid(e).name(), typeid(b).name()) != 0) \
            { \
                wrong_exception = true; \
                caught_str = typeid(e).name(); \
                expecting_str = typeid(b).name(); \
            } \
            else \
                std::cout << "caught: " << e << '\n'; \
        } \
        catch(...) \
        { \
            caught = true; \
            wrong_exception = true; \
            std::cerr << "unknown exception caught" << '\n'; \
        } \
        if(!caught) \
        { \
            this->assert_failed("no exception was caught", static_cast<const char *>(__PRETTY_FUNCTION__), __LINE__); \
        } \
        else \
        { \
            if (wrong_exception) \
            { \
                this->assert_failed("wrong exception caught", static_cast<const char *>(__PRETTY_FUNCTION__), __LINE__); \
                std::cerr << "    - caught: " << caught_str << '\n'; \
                std::cerr << "    - expecting: " << expecting_str << '\n'; \
            } \
            else \
                this->inc_pass(); \
        } \
    }

/// Assert No Exception
///
/// This macro verifies a unit test does not throw an exception. If the unit
/// test throws an exception, the unit test reports a failue and stops.
///
/// @code
///
/// ASSERT_NO_EXCEPTION(blah.do_something()) // unit test fails if throw()
///
/// @endcode
///
#define ASSERT_NO_EXCEPTION(a) \
    { \
        bool caught = false; \
        try{ a; } \
        catch(BaseException &be) { throw; } \
        catch(bfn::general_exception &ge) { caught = true; } \
        catch(std::exception &e) { caught = true; } \
        catch(...) { caught = true; } \
        ASSERT_FALSE(caught); \
    }

/// Run Unittests with Mocks
///
/// When using mocks, it's possible that hippomocks could throw an
/// exception. For example, if you call a function on a mocked class that
/// you have not setup an "OnCall" for. If this happens, a default
/// function within hippomocks is called, that throws an exception.
///
/// To handle these types of issues, mocks should be used inside this
/// function call using a lamda function. This way, if an exeption should
/// occur, the unit test handles it properly. This call will also check
/// to see if the mock's expectations are satisfied. If they are not, it
/// will also fail the unit test.
///
/// @code
///
/// MockRepository mocks;
/// Blah1 *blah1 = mocks.ClassMock<Blah1>();
/// Blah2 *blah2 = new Blah2;
///
/// mocks.OnCall(blah1, Blah1::a).Return(false);
///
/// RUN_UNITTEST_WITH_MOCKS(mocks, [&]
/// {
///     EXPECT_TRUE(blah2->do_something(blah1) == true);
/// });
///
/// @endcode
///
///
#define RUN_UNITTEST_WITH_MOCKS(a,b) \
    this->run_unittest_with_mocks(a,b, static_cast<const char *>(__PRETTY_FUNCTION__), __LINE__);

/// Run Unit Tests
///
/// This runs your unit test. Use the following to kick off your unit tests
///
/// @code
///
/// int
/// main(int argc, char *argv[])
/// {
///     return RUN_ALL_TESTS(<name of unit test class>);
/// }
///
/// @endcode
///
#define RUN_ALL_TESTS(ut) [&]() -> decltype(auto) { (void) argc; (void) argv; ut _ut; return _ut.run(); }()

/// No Delete
///
/// This is used by mock_shared to prevent a shared pointer from performing the
/// deletion of the variable. In this case, mock is doing this for us. Note
/// that this should not be used directly.
///
template<class T> void
no_delete(T *)
{ }

namespace bfn
{

/// Mock Shared
///
/// Use this function to create a mocked version of a shared pointer. This
/// works similar to make_shared, but creates a shared pointer that is created
/// by Hippnomocks. Note that you must provide a mock class, and when that
/// class is destroyed, the pointers being held by shared_ptr are no longer
/// valid.
///
/// @code
/// MockRepository mocks;
/// auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
/// @endcode
///
template<class T> std::shared_ptr<T>
mock_shared(MockRepository &mocks)
{ return std::shared_ptr<T>(mocks.Mock<T>(), no_delete<T>); }

}

// The latests and greatest GCC does not have support for c++14 literals, so
// we need to define them ourselves. Of course it complains if the literal is
// not defined with a "_" so we have our own custom literal here. This should
// be able to be removed once GCC decides to get with the times.

inline std::string
operator ""_s(const char *str, std::size_t len)
{ return std::string(str, len); }

static void
check_exception_type(struct exception_state &state, const std::exception &caught, const std::exception &expected)
{
    state.caught = true;

    if (typeid(caught) != typeid(expected))
    {
        state.wrong_exception = true;
        state.caught_str = std::string(typeid(caught).name());
        state.expecting_str = std::string(typeid(expected).name());
    }
    else
        std::cout << "caught: " << caught << '\n';
}

/// Unit Test
///
/// This class provides the scaffolding needed to perform a unit test. Note
/// that this class also provides support for Hippomocks.
///
/// In general, if you want an example of how to use this class, start with
/// one of the existing unit tests, as they are cookie-cutter in design.
/// For example, take a look at the following:
///
/// @ref debug_ring_ut
///
/// The unit test macros should be used when creating a unit test.
/// @ref EXPECT_TRUE <br>
/// @ref EXPECT_FALSE <br>
/// @ref EXPECT_EXCEPTION <br>
/// @ref EXPECT_NO_EXCEPTION <br>
/// @ref ASSERT_TRUE <br>
/// @ref ASSERT_FALSE <br>
/// @ref ASSERT_EXCEPTION <br>
/// @ref ASSERT_NO_EXCEPTION <br>
///
/// And when a shared_ptr must be created that is being mocked by Hippomocks,
/// be sure to use:
///
/// @ref bfn::mock_shared <br>
///
class unittest
{

    // -------------------------------------------------------------------------
    // Public Interface
    // -------------------------------------------------------------------------

protected:

    /// List Tests
    ///
    /// Override this function to call each of your tests.
    ///
    /// @code
    ///
    /// bool list() override
    /// {
    ///     this->test1()
    ///     this->test2()
    ///
    ///     return true;
    /// }
    ///
    /// @endcode
    ///
    /// @return true if the tests passed, false otherwise
    ///
    virtual bool
    list() { return true; };

    /// Init Tests
    ///
    /// Override this function to initalize your tests. It's better to use
    /// this fucntion than to use your constructor because if the init fails
    /// the unit test will stop, and report failure.
    ///
    /// @code
    ///
    /// bool init() override
    /// {
    ///     <init here>
    ///
    ///     return true;
    /// }
    ///
    /// @endcode
    ///
    /// @return true if the init passed, false otherwise
    ///
    virtual bool
    init() { return true; };

    /// Fini Tests
    ///
    /// Override this function to finalize your tests. It's better to use
    /// this fucntion than to use your destructor because if the fini fails
    /// the unit test will stop, and report failure.
    ///
    /// @code
    ///
    /// bool fini() override
    /// {
    ///     <fini here>
    ///
    ///     return true;
    /// }
    ///
    /// @endcode
    ///
    /// @return true if the fini passed, false otherwise
    ///
    virtual bool
    fini() { return true; };

    template<typename T>
    void run_unittest_with_mocks(MockRepository &mocks, T lamda, const char *func, int line)
    {
        // TODO: Would be great if we could get a printout of the functions
        // that are called that we were not expecting. Would also be great
        // to get a list of calls that we were expecting that were not called.
        //
        // This will require some mods to HippoMocks to store a list of both
        // types of problems, and then get that list when an expection
        // occurs.
        //
        // There also seems to be a lot of logic in HippMocks for the
        // NotImplementedException that doesn't ever seem to be filled in
        // correctly. e.what() always returns "std::exception" but there
        // appears to be logic to fill in e.what() with something else. Would
        // be great to clean that up.

        std::cout << std::uppercase;

        try
        {
            lamda();
        }
        catch (std::exception &e)
        {
            this->expect_failed(e.what(), func, line);
        }

        try
        {
            mocks.VerifyAll();
        }
        catch (std::exception &e)
        {
            this->expect_failed(e.what(), func, line);
        }

        inc_pass();

        mocks.reset();

        // There is an issue with clang-tidy were is basically doesn't see the
        // call to this from hippomocks, so we run it here to silence the
        // warnings. Hippomocks currently doesn't support the reuse of the
        // mocking engine after a call to reset, so it's safe to run this as
        // any code that tries to use the mocking engine will fail regardless.
        MockRepoInstanceHolder<0>::instance = 0;
    }

    void
    compare_exceptions(const struct exception_state &state, gsl::cstring_span<> func, int line)
    {
        if (!state.caught)
        {
            this->expect_failed("no exception was caught", func.data(), line);
        }
        else
        {
            if (state.wrong_exception)
            {
                this->expect_failed("wrong exception caught", func.data(), line);
                std::cerr << "    - caught: " << state.caught_str << 'n';
                std::cerr << "    - expecting: " << state.expecting_str << 'n';
            }
            else
            {
                this->inc_pass();
            }
        }
    }

    /// Expect Exception With Args
    ///
    /// This macro verifies a unit test does throw an exception. If the unit
    /// test does not throw an exception, the unit test reports a failue and
    /// continues testing.
    ///
    /// The first argument is a function that takes no
    /// arguments and returns void.  If the caller wishes to pass a function
    /// that takes arguments, they must first std::bind the arguments
    /// (with appropriate forwarding as needed), and pass the result of the bind
    /// to expect_exception_with_args.
    ///
    /// The second argument is a shared_ptr to an instance of a std::exception
    /// for which the dynamic type is the same as the type seen in the throw statement
    /// in the function-under-test. A shared_ptr is needed to for RTTI to work properly
    /// when the expected exception is compared to the caught exception.
    ///
    /// The third and fourth arguments correspond to __PRETTY_FUNCTION__ and __LINE__
    /// passed from the macro expect_exception.
    ///
    /// @code
    ///
    /// void g(int, double) { throw std::logic_error("error"); };
    ///
    /// class Foo {
    /// public:
    ///     void bar(int a, int b)
    ///     {
    ///         b = b + a;
    ///         throw std::runtime_error("addition error");
    ///     }
    /// };
    ///
    /// int arg1 = 0;
    /// double arg2 = 1.0;
    /// Foo foo;
    ///
    /// auto f1 = std::bind(&Foo::bar, &foo, arg1, arg1);
    /// auto f2 = std::bind(g, arg1, arg2);
    ///
    /// auto e1 = std::shared_ptr<std::exception>(new std::runtime_error("addition error"));
    /// auto e2 = std::shared_ptr<std::exception>(new std::logic_error("error"));
    ///
    /// // unit test succeeds since foo.bar(arg1, arg1) throws runtime_error
    /// this->expect_exception_with_args(f1, e1, func, 50);
    ///
    /// // unit test fails since runtime_error != logic_error
    /// this->expect_exception_with_args(f1, e2, func, 50);
    ///
    /// // unit test succeeds since g(arg1, arg2) throws logic error
    /// this->expect_exception_with_args(f2, e2, func, 4);
    ///
    /// @endcode
    ///
    template <typename F> void
    expect_exception_with_args(F &&f, std::shared_ptr<const std::exception> expected, gsl::cstring_span<> func, int line)
    {
        struct exception_state state = { false, false, "",  "" };

        try { f(); }
        catch (BaseException &be) { throw; }
        catch (bfn::general_exception &ge) { check_exception_type(state, ge, *expected); }
        catch (std::exception &e) { check_exception_type(state, e, *expected); }
        catch (...)
        {
            state.caught = true;
            state.wrong_exception = true;
            std::cerr << "unknown exception caught" << '\n';
        }

        compare_exceptions(state, func, line);
    }

    /// Expect No Exception With Args
    ///
    /// This macro verifies a unit test does not throw an exception. If the unit
    /// test does throw an exception, it reports a failue and
    /// continues testing.
    ///
    /// The first argument is a function that takes no arguments and
    /// returns void.  If the caller wishes to pass a function
    /// that takes arguments, they must first std::bind the arguments
    /// (with appropriate forwarding as needed), and pass the result of the bind
    /// to expect_no_exception_with_args.
    ///
    /// The second and third arguments correspond to __PRETTY_FUNCTION__ and __LINE__
    /// passed in from the expect_no_exception macro.
    ///
    /// @code
    ///
    /// void g(int, double);
    ///
    /// class Foo {
    /// public:
    ///     void bar(int, double);
    /// };
    ///
    /// int arg1 = 0;
    /// double arg2 = 1.0;
    /// Foo foo;
    ///
    /// auto f1 = std::bind(&Foo::bar, &foo, arg1, arg2);
    /// auto f2 = std::bind(g, arg1, arg2);
    ///
    /// // unit test fails if foo.bar(arg1, arg2) throws
    /// this->expect_no_exception_with_args(f1, func, 50);
    ///
    /// // unit test fails if g(arg1, arg2) throws
    /// this->expect_no_exception_with_args(f2, func, 4);
    ///
    /// @endcode
    ///
    template <typename F> void
    expect_no_exception_with_args(F &&f, gsl::cstring_span<> func, int line)
    {
        struct exception_state state = { false, false, "",  "" };

        try { f(); }
        catch (BaseException &be) { throw; }
        catch (bfn::general_exception &ge) { state.caught = true; }
        catch (std::exception &e) { state.caught = true; }
        catch (...) { state.caught = true; }

        this->expect_false_with_args(state.caught, "caught", func, line);
    }

    /// Expect true with args
    ///
    /// This function verifies a condition in a unit test is true.  If the condition is not true,
    /// the unit test reports a failure and continues testing. The macro expect_true passes
    /// the name of the function-under-test and the line on which it is invoked to this function.
    ///
    /// @code
    ///
    /// this->expect_true_with_args(1 == 1, "1 == 1", func, 100) // unit test of func passes at line 100
    /// this->expect_true_with_args(1 == 0, "1 == 0", func, 100) // unit test of func fails at line 100
    ///
    /// @endcode
    ///
    void
    expect_true_with_args(bool condition, gsl::cstring_span<> condition_text, gsl::cstring_span<> func, int line)
    {
        if (condition) { this->inc_pass(); }
        else { this->expect_failed(condition_text.data(), func.data(), line); }
    }

    /// Expect false with args
    ///
    /// This function verifies a condition in a unit test to be false. If the condition is not
    /// false, the unit test reports a failue and continues testing. The macro expect_false
    /// passes the name of the function-under-test and the line on which it is invoked to
    //  this function.
    ///
    /// @code
    ///
    /// this->expect_false_with_args(1 == 1, "1 == 1", func, 10) // unit test of func fails at line 10
    /// this->expect_false_with_args(1 == 0, "1 == 0", func, 10) // unit test of func passes at line 10
    ///
    /// @endcode
    ///
    void
    expect_false_with_args(bool condition, gsl::cstring_span<> condition_text, gsl::cstring_span<> func, int line)
    {
        if (!condition) { this->inc_pass(); }
        else { this->expect_failed(condition_text.data(), func.data(), line); }
    }

protected:

    void inc_pass() { m_pass++; }
    void inc_fail() { m_fail++; }

    // -------------------------------------------------------------------------
    // Private Interface
    // -------------------------------------------------------------------------


private:

    decltype(auto)
    internal_init()
    {
        m_pass = 0;
        m_fail = 0;

        return true;
    }

    decltype(auto)
    internal_fini()
    {
        if (m_fail > 0)
        {
            std::cout << '\n';
            std::cout << "totals: ";
            std::cout << m_pass << " passed, ";
            std::cout << "\033[1;31m";
            std::cout << m_fail << " failed";
            std::cout << "\033[0m";
            std::cout << '\n';

            return false;
        }
        else
        {
            std::cout << "totals: ";
            std::cout << "\033[1;32m";
            std::cout << m_pass << " passed, ";
            std::cout << "\033[0m";
            std::cout << m_fail << " failed";
            std::cout << '\n';

            return true;
        }
    }

public:

    unittest() :
        m_pass(0),
        m_fail(0)
    { }

    virtual ~unittest() {}

    decltype(auto)
    run()
    {
        if (this->internal_init() == false)
            return EXIT_FAILURE;

        if (this->init() == false)
        {
            std::cout << "\033[1;31mFAILED\033[0m: init" << '\n';
            return EXIT_FAILURE;
        }

        try
        {
            if (this->list() == false)
            {
                std::cout << "\033[1;31mFAILED\033[0m: list" << '\n';
                return EXIT_FAILURE;
            }
        }
        catch (...)
        {
        }

        if (this->fini() == false)
        {
            std::cout << "\033[1;31mFAILED\033[0m: fini" << '\n';
            return EXIT_FAILURE;
        }

        if (this->internal_fini() == false)
            return EXIT_FAILURE;

        return EXIT_SUCCESS;
    }

    void
    expect_failed(const char *condition, const char *func, int line)
    {
        std::cout << "\033[1;31mFAILED\033[0m: [" << line << "]: " << func << '\n';
        std::cout << "    - condition: " << condition << '\n';
        this->inc_fail();
    }

    void
    assert_failed(const char *condition, const char *func, int line)
    {
        this->expect_failed(condition, func, line);
        throw (0);
    }

private:

    int m_pass;
    int m_fail;
};

#endif
