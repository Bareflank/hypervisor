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

#include <stdlib.h>
#include <iostream>
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

/// Expect No Exception
///
/// This macro verifies a unit test does not throw an exception. If the unit
/// test throws an exception, the unit test reports a failue and continues
/// testing.
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
        catch(...) { caught = true; } \
        ASSERT_FALSE(caught); \
    }

/// Run Unittests with Mocks
///
/// When using mocks, it's possible that Hippo Mocks could throw an
/// exception. For example, if you call a function on a mocked class that
/// you have not setup an "ExpectCall" for. If this happens, a default
/// function within Hippo Mocks is called, that throws an exception.
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
/// mocks.ExpectCall(blah1, Blah1::a).Return(false);
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
#define RUN_ALL_TESTS(ut) []() -> decltype(auto) { ut _ut; return _ut.run(); }()

class unittest
{

    // =============================================================================
    // Public Interface
    // =============================================================================

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
        try
        {
            lamda();
        }
        catch (std::exception e)
        {
            this->expect_failed("non-implemented function was called", func, line);
        }

        try
        {
            mocks.VerifyAll();
        }
        catch (...)
        {
            this->expect_failed("the mock's expectations were not meet", func, line);
        }

        mocks.reset();
    }

    // =============================================================================
    // Private Interface
    // =============================================================================

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

    unittest() {}
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
        std::cout << "   - condition: " << condition << std::endl;
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
