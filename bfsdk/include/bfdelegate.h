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

///
/// @file bfdelegate.h
///

#ifndef BFDELEGATE_H
#define BFDELEGATE_H

#include <memory>

// -----------------------------------------------------------------------------
// Delegate Definition
// -----------------------------------------------------------------------------

template <
    typename T,
    typename = std::enable_if<std::is_function<T>::value>
    >
class delegate;

// -----------------------------------------------------------------------------
// Delegate Partial Specialization
// -----------------------------------------------------------------------------

/// Delegate
///
/// This delegate class provides the ability to register a call back function
/// that originates from:
/// - A free function
/// - A member function
/// - A lambda function (including capture lists)
///
/// It should be noted that this class attempts to provide the most effcient
/// implementation without the need for malloc / free, or inheritance, at
/// the expense of a very specific syntax requirement.
///
template <
    typename RET,
    typename ...PARAMS
    >
class delegate<RET(PARAMS...)>
{
    using stub_t = RET(*)(void *, PARAMS...);       ///< Stub function type

public:

    /// Default Constructor
    ///
    /// Creates a nullptr delegate. Note that attempts to execute a nullptr
    /// delegate will result in a crash as we do not perform a check for
    /// null
    ///
    delegate() noexcept = default;

    /// Default Destructor
    ///
    ~delegate() noexcept = default;

    /// Is Valid
    ///
    /// @return true if valid, false otherwise
    ///
    constexpr bool is_valid() const noexcept
    { return m_stub != nullptr; }

    /// Is Valid
    ///
    /// @return true if valid, false otherwise
    ///
    constexpr explicit operator bool() const noexcept
    { return is_valid(); }

    /// Create (Member Function Pointer)
    ///
    /// Example usage:
    /// @code
    /// test_class t;
    /// auto d = delegate<int(int)>::create<test_class, &test_class::foo>(&t);
    /// std::cout << "d: " << d(1) << '\n';
    /// @endcode
    ///
    /// @param obj a pointer to the class who's member function will
    ///     be executed.
    /// @return resulting delegate
    ///
    template <
        typename T,
        RET(T::*FUNC)(PARAMS...),
        typename = std::enable_if<std::is_class<T>::value>
        >
    constexpr static delegate create(T &obj) noexcept
    { return delegate(std::addressof(obj), member_stub<T, FUNC>); }

    /// Create (Member Function Pointer Class Pointer)
    ///
    /// Example usage:
    /// @code
    /// test_class t;
    /// auto d = delegate<int(int)>::create<test_class, &test_class::foo>(&t);
    /// std::cout << "d: " << d(1) << '\n';
    /// @endcode
    ///
    /// @param obj a pointer to the class who's member function will
    ///     be executed.
    /// @return resulting delegate
    ///
    template <
        typename T,
        RET(T::*FUNC)(PARAMS...),
        typename = std::enable_if<std::is_class<T>::value>
        >
    constexpr static delegate create(T *obj) noexcept
    { return delegate(obj, member_stub<T, FUNC>); }

    /// Create (Member Function Unique Pointer)
    ///
    /// Example usage:
    /// @code
    /// auto t = make_unique<test_class>();
    /// auto d = delegate<int(int)>::create<test_class, &test_class::foo>(t);
    /// std::cout << "d: " << d(1) << '\n';
    /// @endcode
    ///
    /// @param obj a pointer to the class who's member function will
    ///     be executed.
    /// @return resulting delegate
    ///
    template <
        typename T,
        RET(T::*FUNC)(PARAMS...),
        typename = std::enable_if<std::is_class<T>::value>
        >
    constexpr static delegate create(const std::unique_ptr<T> &obj) noexcept
    { return delegate(obj.get(), member_stub<T, FUNC>); }

    /// Create (Const Member Function Pointer)
    ///
    /// Example usage:
    /// @code
    /// test_class t;
    /// auto d = delegate<int(int)>::create<test_class, &test_class::foo>(&t);
    /// std::cout << "d: " << d(1) << '\n';
    /// @endcode
    ///
    /// @note this function has to have _const appended to it's name because
    ///     MSVC doesn't understand the template overload and fails to
    ///     compile.
    ///
    /// @param obj a pointer to the class who's member function will
    ///     be executed.
    /// @return resulting delegate
    ///
    template <
        typename T,
        RET(T::*FUNC)(PARAMS...) const,
        typename = std::enable_if<std::is_class<T>::value>
        >
    constexpr static delegate create_const(const T &obj) noexcept
    { return delegate(const_cast<T *>(std::addressof(obj)), const_member_stub<T, FUNC>); }

    /// Create (Function Pointer)
    ///
    /// Example usage:
    /// @code
    /// auto d = delegate<int(int)>::create<&foo>();
    /// std::cout << "d: " << d(1) << '\n';
    /// @endcode
    ///
    /// @return resulting delegate
    ///
    template <RET(FUNC)(PARAMS...)>
    constexpr static delegate create() noexcept
    { return delegate(nullptr, function_stub<FUNC>); }

    /// Create (Lambda Pointer)
    ///
    /// Example usage:
    /// @code
    /// test_class t;
    /// auto d = delegate<int(int)>::create([](int val) -> int { return val; });
    /// std::cout << "d: " << d(1) << '\n';
    /// @endcode
    ///
    /// @param ptr a pointer to the lambda function that will
    ///     be executed.
    /// @return resulting delegate
    ///
    template <typename LAMBDA>
    constexpr static delegate create(const LAMBDA &ptr) noexcept
    { return delegate(reinterpret_cast<void *>(const_cast<LAMBDA *>(std::addressof(ptr))), lambda_stub<LAMBDA>); }

    /// Operator ()
    ///
    /// @param params the parameters to pass to the delegate function.
    /// @return the result of executing the delegate function
    ///
    constexpr RET operator()(PARAMS... params) const
    { return (*m_stub)(m_obj, std::forward<PARAMS>(params)...); }

private:

    /// @cond

    // Note:
    //
    // The only public constructor is the default constructor. To create a
    // delegate, use the delegate::create function.
    //

    constexpr explicit delegate(void *obj, stub_t stub) noexcept :
        m_obj(obj),
        m_stub(stub)
    { }

    /// @endcond

private:

    /// @cond

    template <
        typename T,
        RET(T::*FUNC)(PARAMS...),
        typename = std::enable_if<std::is_class<T>::value>
        >
    constexpr static RET member_stub(void *obj, PARAMS... params)
    { return (static_cast<T *>(obj)->*FUNC)(std::forward<PARAMS>(params)...); }

    template <
        typename T,
        RET(T::*FUNC)(PARAMS...) const,
        typename = std::enable_if<std::is_class<T>::value>
        >
    constexpr static RET const_member_stub(void *obj, PARAMS... params)
    { return (static_cast<T *>(obj)->*FUNC)(std::forward<PARAMS>(params)...); }

    template <RET(*FUNC)(PARAMS...)>
    constexpr static RET function_stub(void *, PARAMS... params)
    { return (FUNC)(std::forward<PARAMS>(params)...); }

    template <typename LAMBDA>
    constexpr static RET lambda_stub(void *ptr, PARAMS... params)
    { return (static_cast<LAMBDA *>(ptr)->operator())(std::forward<PARAMS>(params)...); }

    /// @endcond

private:

    void *m_obj{nullptr};       ///< Object containing member function
    stub_t m_stub{nullptr};     ///< Stub that executes the delegate function

public:

    /// @cond

    delegate(const delegate &other) noexcept = default;
    delegate &operator=(const delegate &other) noexcept = default;

    delegate(delegate &&other) noexcept = default;
    delegate &operator=(delegate &&other) noexcept = default;

    /// @endcond
};

#endif
