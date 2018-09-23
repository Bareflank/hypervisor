//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

#ifndef BFMANAGER_H
#define BFMANAGER_H

#include <map>
#include <mutex>
#include <memory>

#include <bfgsl.h>
#include <bfobject.h>

/// Manager
///
/// A generic class for creating, destroying, running and stopping T given a
/// T_factory to actually instantiate T, and a tid to identify which T to
/// interact with.
///
template<typename T, typename T_factory, typename tid>
class bfmanager
{
public:

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~bfmanager() = default;

    /// Get Singleton Instance
    ///
    /// @expects none
    /// @ensures ret != nullptr
    ///
    /// @return a singleton instance of bfmanager
    ///
    static bfmanager *instance() noexcept
    {
        static bfmanager self;
        return &self;
    }

    /// Create T
    ///
    /// Creates T. Note that the T is actually created by the
    /// T factory's make_t function.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param id the t to initialize
    /// @param obj object that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    void create(tid id, bfobject *obj = nullptr)
    {
        auto ___ = gsl::on_failure([&] {
            std::lock_guard<std::mutex> guard(m_mutex);
            m_ts.erase(id);
        });

        if (auto &&t = add_t(id, obj)) {
            t->init(obj);
        }
    }

    /// Destroy T
    ///
    /// Deletes T.
    ///
    /// @param id the t to destroy
    /// @param obj object that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    void destroy(tid id, bfobject *obj = nullptr)
    {
        auto ___ = gsl::finally([&] {
            std::lock_guard<std::mutex> guard(m_mutex);
            m_ts.erase(id);
        });

        if (auto &&t = get_t(id)) {
            t->fini(obj);
        }
    }

    /// Run T
    ///
    /// Executes T.
    ///
    /// @expects t exists
    /// @ensures none
    ///
    /// @param id the t to run
    /// @param obj object that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    void run(tid id, bfobject *obj = nullptr)
    {
        if (auto &&t = get_t(id)) {
            t->run(obj);
        }
    }

    /// Halt T
    ///
    /// Halts T.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param id the t to halt
    /// @param obj object that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    void hlt(tid id, bfobject *obj = nullptr)
    {
        if (auto &&t = get_t(id)) {
            t->hlt(obj);
        }
    }

    /// Set Factory
    ///
    /// Should only be used by unit tests
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param factory the new factory to use
    ///
    void set_factory(std::unique_ptr<T_factory> factory)
    { m_T_factory = std::move(factory); }

private:

    bfmanager() noexcept :
        m_T_factory(std::make_unique<T_factory>())
    { }

    std::unique_ptr<T> &add_t(tid id, bfobject *obj)
    {
        if (auto &&t = get_t(id)) {
            return t;
        }

        if (auto t = m_T_factory->make(id, obj)) {
            std::lock_guard<std::mutex> guard(m_mutex);
            return m_ts[id] = std::move(t);
        }

        throw std::runtime_error("make returned a nullptr");
    }

    std::unique_ptr<T> &get_t(tid id)
    {
        std::lock_guard<std::mutex> guard(m_mutex);
        return m_ts[id];
    }

private:

    std::unique_ptr<T_factory> m_T_factory;
    std::map<tid, std::unique_ptr<T>> m_ts;

    mutable std::mutex m_mutex;

public:

    /// @cond

    bfmanager(bfmanager &&) noexcept = delete;
    bfmanager &operator=(bfmanager &&) noexcept = delete;

    bfmanager(const bfmanager &) = delete;
    bfmanager &operator=(const bfmanager &) = delete;

    /// @endcond
};

#endif
