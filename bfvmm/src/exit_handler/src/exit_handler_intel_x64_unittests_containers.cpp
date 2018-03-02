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

#include <exit_handler/exit_handler_intel_x64_unittests.h>

#ifdef INCLUDE_LIBCXX_UNITTESTS

#include <array>
#include <vector>
#include <deque>
#include <forward_list>
#include <list>
#include <stack>
#include <queue>
#include <set>
#include <map>

void
exit_handler_intel_x64::unittest_1001_containers_array() const
{
    std::array<int, 4> myarray = {{0, 1, 2, 3}};
    std::array<int, 4> myarray2 = {{0, 1, 2, 3}};

    auto total = 0;
    for (auto iter = myarray.begin(); iter != myarray.end(); iter++)
        total += *iter;

    auto rtotal = 0;
    for (auto iter = myarray.rbegin(); iter != myarray.rend(); iter++)
        rtotal += *iter;

    auto ctotal = 0;
    for (auto iter = myarray.cbegin(); iter != myarray.cend(); iter++)
        ctotal += *iter;

    auto crtotal = 0;
    for (auto iter = myarray.crbegin(); iter != myarray.crend(); iter++)
        crtotal += *iter;

    expect_true(total == 6);
    expect_true(rtotal == 6);
    expect_true(ctotal == 6);
    expect_true(crtotal == 6);

    expect_true(myarray.size() == 4);
    expect_true(myarray.max_size() == 4);
    expect_false(myarray.empty());

    expect_true(myarray.at(0) == 0);
    expect_true(myarray.at(3) == 3);
    expect_true(myarray.front() == 0);
    expect_true(myarray.back() == 3);
    expect_true(myarray.data() != nullptr);

    myarray.fill(0);
    myarray.swap(myarray2);

    expect_true(std::get<0>(myarray) == 0);
    expect_true(std::get<3>(myarray) == 3);

    expect_false(myarray == myarray2);
    expect_true(myarray != myarray2);
    expect_false(myarray < myarray2);
    expect_true(myarray > myarray2);
    expect_false(myarray <= myarray2);
    expect_true(myarray >= myarray2);
}

void
exit_handler_intel_x64::unittest_1002_containers_vector() const
{
    auto myvector = std::vector<int>({0, 1, 2, 3});
    auto myvector2 = std::vector<int>({0, 1, 2, 3});

    auto total = 0;
    for (auto iter = myvector.begin(); iter != myvector.end(); iter++)
        total += *iter;

    auto rtotal = 0;
    for (auto iter = myvector.rbegin(); iter != myvector.rend(); iter++)
        rtotal += *iter;

    auto ctotal = 0;
    for (auto iter = myvector.cbegin(); iter != myvector.cend(); iter++)
        ctotal += *iter;

    auto crtotal = 0;
    for (auto iter = myvector.crbegin(); iter != myvector.crend(); iter++)
        crtotal += *iter;

    expect_true(total == 6);
    expect_true(rtotal == 6);
    expect_true(ctotal == 6);
    expect_true(crtotal == 6);

    expect_true(myvector.size() == 4);
    expect_true(myvector.max_size() >= 4);
    myvector.resize(4);
    expect_true(myvector.capacity() >= 4);
    expect_false(myvector.empty());
    myvector.reserve(4);
    myvector.shrink_to_fit();

    expect_true(myvector.at(0) == 0);
    expect_true(myvector.at(3) == 3);
    expect_true(myvector.front() == 0);
    expect_true(myvector.back() == 3);
    expect_true(myvector.data() != nullptr);

    myvector.assign(4, 0);
    myvector = myvector2;

    myvector.push_back(4);
    myvector.pop_back();
    myvector = myvector2;

    myvector.insert(myvector.begin(), 0);
    myvector.erase(myvector.begin());
    myvector = myvector2;

    myvector.swap(myvector2);
    std::swap(myvector, myvector2);

    myvector.emplace(myvector.begin());
    myvector.emplace_back();
    myvector = myvector2;

    expect_true(myvector == myvector2);
    expect_false(myvector != myvector2);
    expect_false(myvector < myvector2);
    expect_false(myvector > myvector2);
    expect_true(myvector <= myvector2);
    expect_true(myvector >= myvector2);
    myvector = myvector2;

    myvector.get_allocator();
    myvector.clear();
}

void
exit_handler_intel_x64::unittest_1003_containers_deque() const
{
    std::deque<int> mydeque = {{0, 1, 2, 3}};
    std::deque<int> mydeque2 = {{0, 1, 2, 3}};

    auto total = 0;
    for (auto iter = mydeque.begin(); iter != mydeque.end(); iter++)
        total += *iter;

    auto rtotal = 0;
    for (auto iter = mydeque.rbegin(); iter != mydeque.rend(); iter++)
        rtotal += *iter;

    auto ctotal = 0;
    for (auto iter = mydeque.cbegin(); iter != mydeque.cend(); iter++)
        ctotal += *iter;

    auto crtotal = 0;
    for (auto iter = mydeque.crbegin(); iter != mydeque.crend(); iter++)
        crtotal += *iter;

    expect_true(total == 6);
    expect_true(rtotal == 6);
    expect_true(ctotal == 6);
    expect_true(crtotal == 6);

    expect_true(mydeque.size() == 4);
    expect_true(mydeque.max_size() >= 4);
    mydeque.resize(4);
    expect_false(mydeque.empty());
    mydeque.shrink_to_fit();

    expect_true(mydeque.at(0) == 0);
    expect_true(mydeque.at(3) == 3);
    expect_true(mydeque.front() == 0);
    expect_true(mydeque.back() == 3);

    mydeque.assign(4, 0);
    mydeque = mydeque2;

    mydeque.push_back(4);
    mydeque.pop_back();
    mydeque = mydeque2;

    mydeque.push_front(4);
    mydeque.pop_front();
    mydeque = mydeque2;

    mydeque.insert(mydeque.begin(), 0);
    mydeque.erase(mydeque.begin());
    mydeque = mydeque2;

    mydeque.swap(mydeque2);
    std::swap(mydeque, mydeque2);

    mydeque.emplace(mydeque.begin());
    mydeque.emplace_back();
    mydeque.emplace_front();
    mydeque = mydeque2;

    expect_true(mydeque == mydeque2);
    expect_false(mydeque != mydeque2);
    expect_false(mydeque < mydeque2);
    expect_false(mydeque > mydeque2);
    expect_true(mydeque <= mydeque2);
    expect_true(mydeque >= mydeque2);
    mydeque = mydeque2;

    mydeque.get_allocator();
    mydeque.clear();
}

void
exit_handler_intel_x64::unittest_1004_containers_forward_list() const
{
    std::forward_list<int> mylist = {{0, 1, 2, 3}};
    std::forward_list<int> mylist2 = {{0, 1, 2, 3}};

    mylist.insert_after(mylist.before_begin(), 10);
    mylist.erase_after(mylist.before_begin());
    mylist.insert_after(mylist.cbefore_begin(), 10);
    mylist.erase_after(mylist.cbefore_begin());
    mylist = mylist2;

    auto total = 0;
    for (auto iter = mylist.begin(); iter != mylist.end(); iter++)
        total += *iter;

    auto ctotal = 0;
    for (auto iter = mylist.cbegin(); iter != mylist.cend(); iter++)
        ctotal += *iter;

    expect_true(total == 6);
    expect_true(ctotal == 6);

    expect_true(mylist.max_size() >= 4);
    expect_false(mylist.empty());
    mylist.resize(4);

    expect_true(mylist.front() == 0);

    mylist.assign(4, 0);
    mylist = mylist2;

    mylist.push_front(4);
    mylist.pop_front();
    mylist = mylist2;

    mylist.swap(mylist2);
    std::swap(mylist, mylist2);

    mylist.emplace_front();
    mylist.emplace_after(mylist.begin());
    mylist = mylist2;

    expect_true(mylist == mylist2);
    expect_false(mylist != mylist2);
    expect_false(mylist < mylist2);
    expect_false(mylist > mylist2);
    expect_true(mylist <= mylist2);
    expect_true(mylist >= mylist2);
    mylist = mylist2;

    mylist.splice_after(mylist.before_begin(), mylist2);
    mylist.remove(0);
    mylist.unique();
    mylist.merge(mylist2, std::greater<int>());
    mylist.sort(std::greater<int>());
    mylist.reverse();
    mylist = mylist2;

    mylist.get_allocator();
    mylist.clear();
}

void
exit_handler_intel_x64::unittest_1005_containers_list() const
{
    std::list<int> mylist = {{0, 1, 2, 3}};
    std::list<int> mylist2 = {{0, 1, 2, 3}};

    auto total = 0;
    for (auto iter = mylist.begin(); iter != mylist.end(); iter++)
        total += *iter;

    auto rtotal = 0;
    for (auto iter = mylist.rbegin(); iter != mylist.rend(); iter++)
        rtotal += *iter;

    auto ctotal = 0;
    for (auto iter = mylist.cbegin(); iter != mylist.cend(); iter++)
        ctotal += *iter;

    auto crtotal = 0;
    for (auto iter = mylist.crbegin(); iter != mylist.crend(); iter++)
        crtotal += *iter;

    expect_true(total == 6);
    expect_true(rtotal == 6);
    expect_true(ctotal == 6);
    expect_true(crtotal == 6);

    expect_true(mylist.size() == 4);
    expect_true(mylist.max_size() >= 4);
    expect_false(mylist.empty());
    mylist.resize(4);

    expect_true(mylist.front() == 0);
    expect_true(mylist.back() == 3);

    mylist.assign(4, 0);
    mylist = mylist2;

    mylist.push_back(4);
    mylist.pop_back();
    mylist = mylist2;

    mylist.push_front(4);
    mylist.pop_front();
    mylist = mylist2;

    mylist.insert(mylist.begin(), 0);
    mylist.erase(mylist.begin());
    mylist = mylist2;

    mylist.swap(mylist2);
    std::swap(mylist, mylist2);

    mylist.emplace(mylist.begin());
    mylist.emplace_back();
    mylist.emplace_front();
    mylist = mylist2;

    expect_true(mylist == mylist2);
    expect_false(mylist != mylist2);
    expect_false(mylist < mylist2);
    expect_false(mylist > mylist2);
    expect_true(mylist <= mylist2);
    expect_true(mylist >= mylist2);
    mylist = mylist2;

    mylist.splice(mylist.begin(), mylist2);
    mylist.remove(0);
    mylist.unique();
    mylist.merge(mylist2, std::greater<int>());
    mylist.sort(std::greater<int>());
    mylist.reverse();
    mylist = mylist2;

    mylist.get_allocator();
    mylist.clear();
}

void
exit_handler_intel_x64::unittest_1006_containers_stack() const
{
    std::stack<int> mystack{{0, 1, 2, 3}};
    std::stack<int> mystack2{{0, 1, 2, 3}};

    expect_true(mystack.size() == 4);
    expect_false(mystack.empty());

    expect_true(mystack.top() == 3);

    mystack.push(4);
    mystack.pop();

    mystack.emplace();
    mystack.pop();

    mystack.swap(mystack2);
    std::swap(mystack, mystack2);

    expect_true(mystack == mystack2);
    expect_false(mystack != mystack2);
    expect_false(mystack < mystack2);
    expect_false(mystack > mystack2);
    expect_true(mystack <= mystack2);
    expect_true(mystack >= mystack2);
}

void
exit_handler_intel_x64::unittest_1007_containers_queue() const
{
    std::queue<int> myqueue{{0, 1, 2, 3}};
    std::queue<int> myqueue2{{0, 1, 2, 3}};

    expect_true(myqueue.size() == 4);
    expect_false(myqueue.empty());

    expect_true(myqueue.front() == 0);
    expect_true(myqueue.back() == 3);

    myqueue.emplace();
    myqueue.push(1);
    myqueue.push(2);
    myqueue.push(3);

    myqueue.pop();
    myqueue.pop();
    myqueue.pop();
    myqueue.pop();

    myqueue.swap(myqueue2);
    std::swap(myqueue, myqueue2);

    expect_true(myqueue == myqueue2);
    expect_false(myqueue != myqueue2);
    expect_false(myqueue < myqueue2);
    expect_false(myqueue > myqueue2);
    expect_true(myqueue <= myqueue2);
    expect_true(myqueue >= myqueue2);
}

void
exit_handler_intel_x64::unittest_1008_containers_priority_queue() const
{
    int myints[] = {0, 1, 2, 3};

    auto myqueue = std::priority_queue<int>(myints, myints + 4);
    auto myqueue2 = std::priority_queue<int>(myints, myints + 4);

    expect_true(myqueue.size() == 4);
    expect_false(myqueue.empty());

    expect_true(myqueue.top() == 3);

    myqueue.emplace();
    myqueue.push(1);
    myqueue.push(2);
    myqueue.push(3);

    myqueue.pop();
    myqueue.pop();
    myqueue.pop();
    myqueue.pop();

    myqueue.swap(myqueue2);
    std::swap(myqueue, myqueue2);
}

void
exit_handler_intel_x64::unittest_1009_containers_set() const
{
    auto myset = std::set<int>({0, 1, 2, 3});
    auto myset2 = std::set<int>({0, 1, 2, 3});

    auto total = 0;
    for (auto iter = myset.begin(); iter != myset.end(); iter++)
        total += *iter;

    auto rtotal = 0;
    for (auto iter = myset.rbegin(); iter != myset.rend(); iter++)
        rtotal += *iter;

    auto ctotal = 0;
    for (auto iter = myset.cbegin(); iter != myset.cend(); iter++)
        ctotal += *iter;

    auto crtotal = 0;
    for (auto iter = myset.crbegin(); iter != myset.crend(); iter++)
        crtotal += *iter;

    expect_true(total == 6);
    expect_true(rtotal == 6);
    expect_true(ctotal == 6);
    expect_true(crtotal == 6);

    expect_true(myset.size() == 4);
    expect_true(myset.max_size() >= 4);
    expect_false(myset.empty());

    myset.insert(myset.begin(), 0);
    myset.erase(myset.begin());
    myset = myset2;

    myset.swap(myset2);
    myset.swap(myset2);

    myset.emplace();
    myset.emplace_hint(myset.begin());
    myset = myset2;

    myset.key_comp();
    myset.value_comp();

    expect_true(myset.find(0) != myset.end());
    expect_true(myset.count(0) == 1);
    expect_true(myset.lower_bound(0) != myset.end());
    expect_true(myset.upper_bound(0) != myset.end());
    myset.equal_range(0);

    myset.get_allocator();
    myset.clear();
}

void
exit_handler_intel_x64::unittest_100A_containers_map() const
{
    auto mymap = std::map<int, int>();
    auto mymap2 = std::map<int, int>();

    mymap2[0] = 0;
    mymap2[1] = 1;
    mymap2[2] = 2;
    mymap2[3] = 3;

    mymap = mymap2;

    auto total = 0;
    for (auto iter = mymap.begin(); iter != mymap.end(); iter++)
        total += iter->second;

    auto rtotal = 0;
    for (auto iter = mymap.rbegin(); iter != mymap.rend(); iter++)
        rtotal += iter->second;

    auto ctotal = 0;
    for (auto iter = mymap.cbegin(); iter != mymap.cend(); iter++)
        ctotal += iter->second;

    auto crtotal = 0;
    for (auto iter = mymap.crbegin(); iter != mymap.crend(); iter++)
        crtotal += iter->second;

    expect_true(total == 6);
    expect_true(rtotal == 6);
    expect_true(ctotal == 6);
    expect_true(crtotal == 6);

    expect_true(mymap.size() == 4);
    expect_true(mymap.max_size() >= 4);
    expect_false(mymap.empty());

    expect_true(mymap.at(0) == 0);
    expect_true(mymap.at(3) == 3);

    mymap.insert(std::pair<int, int>(4, 4));
    mymap.erase(4);
    mymap = mymap2;

    mymap.swap(mymap2);
    mymap.swap(mymap2);

    mymap.emplace();
    mymap.emplace_hint(mymap.begin(), std::pair<int, int>(4, 4));
    mymap = mymap2;

    mymap.key_comp();
    mymap.value_comp();

    expect_true(mymap.find(0) != mymap.end());
    expect_true(mymap.count(0) == 1);
    expect_true(mymap.lower_bound(0) != mymap.end());
    expect_true(mymap.upper_bound(0) != mymap.end());
    mymap.equal_range(0);

    mymap.get_allocator();
    mymap.clear();
}

#endif
