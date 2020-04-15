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
/// @file detector.hpp
///

#ifndef BSL_DETECTOR_HPP
#define BSL_DETECTOR_HPP

#include "../false_type.hpp"
#include "../true_type.hpp"
#include "../type_identity.hpp"
#include "../void_t.hpp"

namespace bsl
{
    namespace details
    {
        /// @class bsl::detector
        ///
        /// <!-- description -->
        ///   @brief The alias template detector is an alias for an unspecified
        ///     class type with two public member typedefs value_t and type,
        ///     which are defined as follows:
        ///     - If the template-id OP<ARGS...> denotes a valid type, then
        ///       value_t is an alias for bsl::true_type, and type is an alias
        ///       for OP<ARGS...>;
        ///     - Otherwise, value_t is an alias for bsl::false_type and type is
        ///       an alias for DEFAULT.
        ///
        /// <!-- template parameters -->
        ///   @tparam DEFAULT the default type to return when OP<ARGS...> is
        ///     invalid
        ///   @tparam VOID Always void (performs that actual detection)
        ///   @tparam OP the operation to detect
        ///   @tparam ARGS the arguments to the operation to detect
        ///
        template<typename DEFAULT, typename VOID, template<class...> class OP, typename... ARGS>
        struct detector final
        {
            /// @brief provides the member typedef "type"
            using type = DEFAULT;
            /// @brief provides the member typedef "value_t"
            using value_t = false_type;
        };

        /// @cond doxygen off

        template<typename DEFAULT, template<class...> class OP, typename... ARGS>
        struct detector<DEFAULT, void_t<OP<ARGS...>>, OP, ARGS...> final
        {
            /// @brief provides the member typedef "type"
            using type = OP<ARGS...>;
            /// @brief provides the member typedef "value_t"
            using value_t = true_type;
        };

        /// @endcond doxygen on
    }
}

#endif
