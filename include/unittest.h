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

#define NO_HIPPOMOCKS_NAMESPACE

#ifdef OS_LINUX
#define LINUX_TARGET
#endif

#include <stdlib.h>
#include <iostream>
#include <exception.h>
#include <hippomocks.h>

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
    else { this->expect_failed(#condition, __PRETTY_FUNCTION__, __LINE__); }

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
    else { this->expect_failed(#condition, __PRETTY_FUNCTION__, __LINE__); }

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
                std::cout << "caught: " << ge << std::endl; \
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
                std::cout << "caught: " << e << std::endl; \
        } \
        catch(...) \
        { \
            caught = true; \
            wrong_exception = true; \
            std::cerr << "unknown exception caught" << std::endl; \
        } \
        if(caught == false) \
        { \
            this->expect_failed("no exception was caught", __PRETTY_FUNCTION__, __LINE__); \
        } \
        else \
        { \
            if (wrong_exception == true) \
            { \
                this->expect_failed("wrong exception caught", __PRETTY_FUNCTION__, __LINE__); \
                std::cerr << "    - caught: " << caught_str << std::endl; \
                std::cerr << "    - expecting: " << expecting_str << std::endl; \
            } \
            else \
                this->inc_pass(); \
        } \
    }

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
    else { this->assert_failed(#condition, __PRETTY_FUNCTION__, __LINE__); }

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
    else { this->assert_failed(#condition, __PRETTY_FUNCTION__, __LINE__); }

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
                std::cout << "caught: " << ge << std::endl; \
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
                std::cout << "caught: " << e << std::endl; \
        } \
        catch(...) \
        { \
            caught = true; \
            wrong_exception = true; \
            std::cerr << "unknown exception caught" << std::endl; \
        } \
        if(caught == false) \
        { \
            this->assert_failed("no exception was caught", __PRETTY_FUNCTION__, __LINE__); \
        } \
        else \
        { \
            if (wrong_exception == true) \
            { \
                this->assert_failed("wrong exception caught", __PRETTY_FUNCTION__, __LINE__); \
                std::cerr << "    - caught: " << caught_str << std::endl; \
                std::cerr << "    - expecting: " << expecting_str << std::endl; \
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
    this->run_unittest_with_mocks(a,b, __PRETTY_FUNCTION__, __LINE__);

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
    }

    // -------------------------------------------------------------------------
    // Private Interface
    // -------------------------------------------------------------------------

protected:

    void inc_pass() { m_pass++; }
    void inc_fail() { m_fail++; }

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
            std::cout << std::endl;
            std::cout << "totals: ";
            std::cout << m_pass << " passed, ";
            std::cout << "\033[1;31m";
            std::cout << m_fail << " failed";
            std::cout << "\033[0m";
            std::cout << std::endl;

            return false;
        }
        else
        {
            std::cout << "totals: ";
            std::cout << "\033[1;32m";
            std::cout << m_pass << " passed, ";
            std::cout << "\033[0m";
            std::cout << m_fail << " failed";
            std::cout << std::endl;

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
            std::cout << "\033[1;31mFAILED\033[0m: init" << std::endl;
            return EXIT_FAILURE;
        }

        try
        {
            if (this->list() == false)
            {
                std::cout << "\033[1;31mFAILED\033[0m: list" << std::endl;
                return EXIT_FAILURE;
            }
        }
        catch (...)
        {
        }

        if (this->fini() == false)
        {
            std::cout << "\033[1;31mFAILED\033[0m: fini" << std::endl;
            return EXIT_FAILURE;
        }

        if (this->internal_fini() == false)
            return EXIT_FAILURE;

        return EXIT_SUCCESS;
    }

    void
    expect_failed(const char *condition, const char *func, int line)
    {
        std::cout << "\033[1;31mFAILED\033[0m: [" << line << "]: " << func << std::endl;
        std::cout << "    - condition: " << condition << std::endl;
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
