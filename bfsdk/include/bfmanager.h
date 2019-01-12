//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef BFMANAGER_H
#define BFMANAGER_H

#include <mutex>
#include <memory>
#include <unordered_map>

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
    /// @param id the T to initialize
    /// @param obj object that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    void create(tid id, bfobject *obj = nullptr)
    {
        try {
            if (auto t = add_t(id, obj)) {
                t->init(obj);
            }
        }
        catch (...) {
            std::lock_guard<std::mutex> guard(m_mutex);
            m_ts.erase(id);

            throw;
        }
    }

    /// Destroy T
    ///
    /// Deletes T.
    ///
    /// @param id the T to destroy
    /// @param obj object that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    void destroy(tid id, bfobject *obj = nullptr)
    {
        if (auto t = get(id)) {
            t->fini(obj);
        }

        std::lock_guard<std::mutex> guard(m_mutex);
        m_ts.erase(id);
    }

    /// Run T
    ///
    /// Executes T.
    ///
    /// @expects t exists
    /// @ensures none
    ///
    /// @param id the T to run
    /// @param obj object that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    void run(tid id, bfobject *obj = nullptr)
    {
        if (auto t = get(id)) {
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
    /// @param id the T to halt
    /// @param obj object that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    void hlt(tid id, bfobject *obj = nullptr)
    {
        if (auto t = get(id)) {
            t->hlt(obj);
        }
    }

    /// Get
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param id the T to get
    /// @param err the error to display
    /// @return returns a pointer to the T associated with tid
    ///
    gsl::not_null<T *> get(tid id, const char *err = nullptr)
    {
        std::lock_guard<std::mutex> guard(m_mutex);

        if (auto iter = m_ts.find(id); iter != m_ts.end()) {
            return iter->second.get();
        }

        if (err != nullptr) {
            throw std::runtime_error(err);
        }
        else {
            throw std::runtime_error("bfmanager: failed to get T");
        }
    }

    /// Get (Dynamic Cast)
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param id the T to get
    /// @param err the error to display
    /// @return returns a pointer to the T associated with tid
    ///
    template<typename U>
    gsl::not_null<U> get(tid id, const char *err = nullptr)
    { return dynamic_cast<U>(get(id, err).get()); }

private:

    bfmanager() noexcept :
        m_T_factory(std::make_unique<T_factory>())
    { }

    gsl::not_null<T *> add_t(tid id, bfobject *obj)
    {
        if (auto iter = m_ts.find(id); iter != m_ts.end()) {
            return iter->second.get();
        }

        if (auto t = m_T_factory->make(id, obj)) {
            std::lock_guard<std::mutex> guard(m_mutex);

            auto ptr = t.get();
            m_ts[id] = std::move(t);

            return ptr;
        }

        throw std::runtime_error("make returned a nullptr");
    }

private:

    std::unique_ptr<T_factory> m_T_factory;
    std::unordered_map<tid, std::unique_ptr<T>> m_ts;

    mutable std::mutex m_mutex;

public:

    /// @cond

    void set_factory(std::unique_ptr<T_factory> factory)
    { m_T_factory = std::move(factory); }

    /// @endcond

public:

    /// @cond

    bfmanager(bfmanager &&) noexcept = delete;
    bfmanager &operator=(bfmanager &&) noexcept = delete;

    bfmanager(const bfmanager &) = delete;
    bfmanager &operator=(const bfmanager &) = delete;

    /// @endcond
};

#endif
