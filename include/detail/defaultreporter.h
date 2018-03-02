// HippoMocks, a library for using mocks in unit testing of C++ code.
// Copyright (C) 2008, Bas van Tiel, Christian Rexwinkel, Mike Looijmans,
// Peter Bindels
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
//
// You can also retrieve it from http://www.gnu.org/licenses/lgpl-2.1.html

#ifndef HIPPOMOCKS_DEFAULTREPORTER_H
#define HIPPOMOCKS_DEFAULTREPORTER_H

#ifndef DEBUGBREAK
#ifdef _MSC_VER
extern "C" __declspec(dllimport) int WINCALL IsDebuggerPresent();
extern "C" __declspec(dllimport) void WINCALL DebugBreak();
#define DEBUGBREAK(e) if (IsDebuggerPresent()) DebugBreak(); else (void)0
#else
#define DEBUGBREAK(e)
#endif
#endif

#if !defined(HM_NO_EXCEPTIONS)
#include <iostream>
#include <sstream>
#include <cstring>

inline std::ostream &operator<<(std::ostream &os, const Call &call)
{
    os << call.fileName << "(" << call.lineno << ") ";
    if (call.expectation == Once)
        os << "Expectation for ";
    else
        os << "Result set for ";

    os << call.funcName;

    call.printArgs(os);

    os << " on the mock at 0x" << call.mock << " was ";

    if (!call.isSatisfied())
        os << "not ";

    if (call.expectation == Once)
        os << "satisfied." << std::endl;
    else
        os << "used." << std::endl;

    return os;
}

inline std::ostream &operator<<(std::ostream &os, const MockRepository &repo)
{
    if (repo.expectations.size())
    {
        os << "Expectations set:" << std::endl;
        for (auto &exp : repo.expectations)
            os << *exp;
        os << std::endl;
    }

    if (repo.neverCalls.size())
    {
        os << "Functions explicitly expected to not be called:" << std::endl;
        for (auto &nc : repo.neverCalls)
            os << *nc;
        os << std::endl;
    }

    if (repo.optionals.size())
    {
        os << "Optional results set up:" << std::endl;
        for (auto &opt : repo.optionals)
            os << *opt;
        os << std::endl;
    }
    return os;
}

#include <exception>
#ifndef BASE_EXCEPTION
#define BASE_EXCEPTION std::exception
#endif
#define RAISEEXCEPTION(e)           { DEBUGBREAK(e); if (std::uncaught_exception()) latentException = [=, &repo]{ throw e; }; else throw e; }

class BaseException
    : public BASE_EXCEPTION
{
public:
    ~BaseException() throw() {}
    const char *what() const throw() { return txt.c_str(); }
protected:
    std::string txt;
};

class ExpectationException : public BaseException
{
public:
    ExpectationException(MockRepository &repo, const std::string &args, const char *funcName)
    {
        std::stringstream text;
        text << "Function " << funcName << args << " called with mismatching expectation!" << std::endl;
        text << repo;
        txt = text.str();
    }
};

#ifdef LINUX_TARGET
#include <execinfo.h>
#endif

class NotImplementedException : public BaseException
{
public:
    NotImplementedException(MockRepository &repo)
    {
        std::stringstream text;
        text << "Function called without expectation!" << std::endl;
        text << repo;

#ifdef LINUX_TARGET
        void *stacktrace[256];
        size_t size = backtrace(stacktrace, sizeof(stacktrace));
        if (size > 0)
        {
            text << "Stackdump:" << std::endl;
            char **symbols = backtrace_symbols(stacktrace, size);
            for (size_t i = 0; i < size; i = i + 1)
            {
                text << symbols[i] << std::endl;
            }
            free(symbols);
        }
#endif

        txt = text.str();
    }
};

class CallMissingException : public BaseException
{
public:
    CallMissingException(MockRepository &repo)
    {
        std::stringstream text;
        text << "Function with expectation not called!" << std::endl;
        text << repo;
        txt = text.str();
    }
};

class ZombieMockException : public BaseException
{
public:
    ZombieMockException(MockRepository &repo)
    {
        std::stringstream text;
        text << "Function called on mock that has already been destroyed!" << std::endl;
        text << repo;

#ifdef LINUX_TARGET
        void *stacktrace[256];
        size_t size = backtrace(stacktrace, sizeof(stacktrace));
        if (size > 0)
        {
            text << "Stackdump:" << std::endl;
            char **symbols = backtrace_symbols(stacktrace, size);
            for (size_t i = 0; i < size; i = i + 1)
            {
                text << symbols[i] << std::endl;
            }
            free(symbols);
        }
#endif

        txt = text.str();
    }
};

class NoResultSetUpException : public BaseException
{
public:
    NoResultSetUpException(MockRepository &repo, const std::string &args, const char *funcName)
    {
        std::stringstream text;
        text << "No result set up on call to " << funcName << args << std::endl << repo;

#ifdef LINUX_TARGET
        void *stacktrace[256];
        size_t size = backtrace(stacktrace, sizeof(stacktrace));
        if (size > 0)
        {
            text << "Stackdump:" << std::endl;
            char **symbols = backtrace_symbols(stacktrace, size);
            for (size_t i = 0; i < size; i = i + 1)
            {
                text << symbols[i] << std::endl;
            }
            free(symbols);
        }
#endif

        txt = text.str();
    }
};

inline Reporter *GetDefaultReporter()
{
    static struct DefaultReporter : Reporter
    {
        DefaultReporter() : latentException([] {}) {}
        std::function<void()> latentException;
        void CallMissing(Call &call, MockRepository &repo) override
        {
            (void)call;
            RAISEEXCEPTION(CallMissingException(repo));
        }
        void ExpectationExceeded(Call &call, MockRepository &repo, const std::string &args, const char *funcName) override
        {
            (void)call;
            RAISEEXCEPTION(ExpectationException(repo, args, funcName));
        }
        void FunctionCallToZombie(MockRepository &repo, const std::string &args) override
        {
            (void)args;
            RAISEEXCEPTION(ZombieMockException(repo));
        }
        void InvalidBaseOffset(size_t baseOffset, MockRepository &repo) override
        {
            (void)baseOffset;
            (void)repo;
            std::terminate();
        }
        void InvalidFuncIndex(size_t funcIndex, MockRepository &repo) override
        {
            (void)funcIndex;
            (void)repo;
            std::terminate();
        }
        void NoExpectationMatches(MockRepository &repo, const std::string &args, const char *funcName) override
        {
            RAISEEXCEPTION(ExpectationException(repo, args, funcName));
        }
        void NoResultSetUp(Call &call, MockRepository &repo, const std::string &args, const char *funcName) override
        {
            (void)call;
            RAISEEXCEPTION(NoResultSetUpException(repo, args, funcName));
        }
        void UnknownFunction(MockRepository &repo) override
        {
            RAISEEXCEPTION(NotImplementedException(repo));
        }
        void TestStarted() override
        {
            latentException = [] {};
        }
        void TestFinished() override
        {
            if (!std::uncaught_exception() && latentException)
            {
                latentException();
            }
        }
    } defaultReporter;
    return &defaultReporter;
}

#endif

#endif
