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

#ifndef HIPPOMOCKS_REPORTER_H
#define HIPPOMOCKS_REPORTER_H

class Call;

class Reporter
{
public:
    virtual void CallMissing(Call &call, MockRepository &repo) = 0;
    virtual void ExpectationExceeded(Call &call, MockRepository &repo, const std::string &args, const char *funcName) = 0;
    virtual void FunctionCallToZombie(MockRepository &repo, const std::string &args) = 0;
    virtual void InvalidBaseOffset(size_t baseOffset, MockRepository &repo) = 0;
    virtual void InvalidFuncIndex(size_t funcIndex, MockRepository &repo) = 0;
    virtual void NoExpectationMatches(MockRepository &repo, const std::string &args, const char *funcName) = 0;
    virtual void NoResultSetUp(Call &call, MockRepository &repo, const std::string &args, const char *funcName) = 0;
    virtual void UnknownFunction(MockRepository &repo) = 0;
    virtual void TestStarted() = 0;
    virtual void TestFinished() = 0;
};

Reporter *GetDefaultReporter();
#endif
