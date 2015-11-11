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

#define EXPECT_TRUE(condition) \
    if((condition)) { this->inc_pass(); } \
    else { this->expect_failed(#condition, __PRETTY_FUNCTION__, __LINE__); }
#define EXPECT_FALSE(condition) \
    if(!(condition)) { this->inc_pass(); } \
    else { this->expect_failed(#condition, __PRETTY_FUNCTION__, __LINE__); }

#define ASSERT_TRUE(condition) \
    if((condition)) { this->inc_pass(); } \
    else { this->assert_failed(#condition, __PRETTY_FUNCTION__, __LINE__); }
#define ASSERT_FALSE(condition) \
    if(!(condition)) { this->inc_pass(); } \
    else { this->assert_failed(#condition, __PRETTY_FUNCTION__, __LINE__); }

#define RUN_ALL_TESTS(ut) []() -> int { ut _ut; return _ut.run(); }()

class unittest
{
public:

    unittest() {}
    virtual ~unittest() {}

    virtual int run(void)
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

    virtual void expect_failed(const char *condition, const char *func, int line)
    {
        std::cout << "\033[1;31mFAILED\033[0m: [" << line << "]: " << func << std::endl;
        std::cout << "   - condition: " << condition << std::endl;
        this->inc_fail();
    }

    virtual void assert_failed(const char *condition, const char *func, int line)
    {
        this->expect_failed(condition, func, line);
        throw (0);
    }

protected:

    virtual bool list(void) { return true; };
    virtual bool init(void) { return true; };
    virtual bool fini(void) { return true; };

    virtual void inc_pass(void) { m_pass++; }
    virtual void inc_fail(void) { m_fail++; }

private:

    virtual bool internal_init(void)
    {
        m_pass = 0;
        m_fail = 0;

        return true;
    }

    virtual bool internal_fini(void)
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

private:

    int m_pass;
    int m_fail;
};

#endif
