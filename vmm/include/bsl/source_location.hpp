/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///
/// @file source_location.hpp
///

#ifndef BSL_SOURCE_LOCATION_HPP
#define BSL_SOURCE_LOCATION_HPP

#include "cstdint.hpp"
#include "cstr_type.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief This class implements the source_location specification that
    ///     will eventually be included in C++20. We make some changes to the
    ///     specification to support AUTOSAR, but these changes should not
    ///     change how the code is compiled or used, with the exception that
    ///     we do not include the column() as this does not seem to be
    ///     implemented by any compilers yet.
    ///   @include example_source_location_overview.hpp
    ///
    class source_location final
    {
        /// @brief defines the source location's file name type
        using file_type = cstr_type;
        /// @brief defines the source location's function name type
        using func_type = cstr_type;
        /// @brief defines the source location's line location type
        using line_type = bsl::intmax;

        /// <!-- description -->
        ///   @brief constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param current_file the file name of the source
        ///   @param current_func the function name of the source
        ///   @param current_line the line location of the source
        ///
        constexpr source_location(                    // --
            file_type const current_file,             // --
            func_type const current_func,             // --
            line_type const current_line) noexcept    // --
            : m_file{current_file}                    // --
            , m_func{current_func}                    // --
            , m_line{current_line}
        {}

    public:
        /// <!-- description -->
        ///   @brief Creates a default constructed source location. By default,
        ///     a source location's file name is "unknown", the function name
        ///     is "unknown" and the line location is "-1".
        ///   @include source_location/example_source_location_default_constructor.hpp
        ///
        constexpr source_location() noexcept    // --
            : m_file{"unknown"}                 // --
            , m_func{"unknown"}                 // --
            , m_line{-1}
        {}

        /// <!-- description -->
        ///   @brief Constructs a new source_location object corresponding to
        ///     the location of the call site.
        ///   @include source_location/example_source_location_current.hpp
        ///
        /// <!-- notes -->
        ///   @note You should not set the parameters manually. Instead,
        ///     use the default parameters which will contain the location
        ///     information provided by the compiler.
        ///   @note We DO NOT ensure by contract that the source location
        ///     contains valid pointers for the file name and function name
        ///     which means the resulting source_location could return
        ///     a nullptr for both the file name and function name. Care should
        ///     be taken to ensure the proper checks are made as needed.
        ///   @note Instead of using bsl::source_location::current() to get
        ///     the current source_location, use bsl::here() which provides a
        ///     function with less verbosity.
        ///
        /// <!-- inputs/outputs -->
        ///   @param current_file defaults to the current file name
        ///   @param current_func defaults to the current function name
        ///   @param current_line defaults to the current line location
        ///   @return returns a new source_location object corresponding to
        ///     the location of the call site of current().
        ///
        static constexpr source_location
        current(
            file_type const current_file = BSL_BUILTIN_FILE,
            func_type const current_func = BSL_BUILTIN_FUNCTION,
            line_type const current_line = BSL_BUILTIN_LINE) noexcept
        {
            return {current_file, current_func, current_line};
        }

        /// <!-- description -->
        ///   @brief Returns the file name associated with the
        ///     bsl::source_location
        ///   @include source_location/example_source_location_file_name.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns the file name associated with the
        ///
        [[nodiscard]] constexpr file_type
        file_name() const noexcept
        {
            return m_file;
        }

        /// <!-- description -->
        ///   @brief Returns the function name associated with the
        ///     bsl::source_location
        ///   @include source_location/example_source_location_function_name.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns the function name associated with the
        ///
        [[nodiscard]] constexpr func_type
        function_name() const noexcept
        {
            return m_func;
        }

        /// <!-- description -->
        ///   @brief Returns the line location associated with the
        ///     bsl::source_location
        ///   @include source_location/example_source_location_line.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns the line location associated with the
        ///
        [[nodiscard]] constexpr line_type
        line() const noexcept
        {
            return m_line;
        }

    private:
        /// @brief stores the file name of the bsl::source_location
        file_type m_file;
        /// @brief stores the function name of the bsl::source_location
        func_type m_func;
        /// @brief stores the line location of the bsl::source_location
        line_type m_line;
    };

    /// <!-- description -->
    ///   @brief This provides a less verbose version of
    ///     bsl::source_location::current() to help reduce how large this
    ///     code must be. They are equivalent, and should not produce any
    ///     additional overhead in release mode.
    ///   @include source_location/example_source_location_here.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @param sloc the source_location object corresponding to
    ///     the location of the call site.
    ///   @return the source_location object corresponding to
    ///     the location of the call site.
    ///
    constexpr source_location
    here(source_location const &sloc = source_location::current()) noexcept
    {
        return sloc;
    }

    /// @brief defines the type used to describe a bsl::source_location
    using sloc_type = source_location;
}    // namespace bsl

#endif
