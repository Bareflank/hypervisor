/*
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef BFDEBUG_H
#define BFDEBUG_H

#include <bfconstants.h>

/** @cond */

/* -------------------------------------------------------------------------- */
/* C++ Debugging                                                              */
/* -------------------------------------------------------------------------- */

#ifdef __cplusplus

#include <bfgsl.h>
#include <bfstring.h>

#include <exception>
#include <type_traits>

#ifdef _MSC_VER
#define bfcolor_black ""
#define bfcolor_red ""
#define bfcolor_green ""
#define bfcolor_yellow ""
#define bfcolor_blue ""
#define bfcolor_magenta ""
#define bfcolor_cyan ""
#define bfcolor_end ""
#else
#define bfcolor_black "\033[1;30m"
#define bfcolor_red "\033[1;31m"
#define bfcolor_green "\033[1;32m"
#define bfcolor_yellow "\033[1;33m"
#define bfcolor_blue "\033[1;34m"
#define bfcolor_magenta "\033[1;35m"
#define bfcolor_cyan "\033[1;36m"
#define bfcolor_end "\033[0m"
#endif

#define bfcolor_debug bfcolor_green
#define bfcolor_alert bfcolor_yellow
#define bfcolor_error bfcolor_red

using cstr_t = const char *;

#ifdef UNIX
#define __BFFUNC__ static_cast<cstr_t>(__PRETTY_FUNCTION__)
#else
#define __BFFUNC__ static_cast<cstr_t>(__FUNCTION__)
#endif

#ifdef VMM
extern "C" uint64_t thread_context_cpuid(void);
extern "C" uint64_t write_str(const std::string &str);
#else
#include <iostream>
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4312)
#endif

template <
    typename T,
    typename = std::enable_if_t <
        std::is_pointer<T>::value ||
        std::is_integral<T>::value
        >
    >
const void *
view_as_pointer(const T val)
{ return reinterpret_cast<const void *>(val); }

#ifdef _MSC_VER
#pragma warning(pop)
#endif

extern "C" uint64_t
unsafe_write_cstr(const char *cstr, size_t len);

#include <typeinfo>

#ifdef _MSC_VER

template<typename T>
std::string type_name()
{ return typeid(T).name(); }

template<typename T>
std::string type_name(const T &t)
{ return typeid(t).name(); }

#else

#include <cxxabi.h>

template<typename T>
std::string type_name()
{
    int status;
    std::string name = typeid(T).name();

    auto demangled_name =
        abi::__cxa_demangle(name.c_str(), nullptr, nullptr, &status);

    if (status == 0) {
        name = demangled_name;
        std::free(demangled_name);
    }

    return name;
}

template<typename T>
std::string type_name(const T &t)
{
    int status;
    std::string name = typeid(t).name();

    auto demangled_name =
        abi::__cxa_demangle(name.c_str(), nullptr, nullptr, &status);

    if (status == 0) {
        name = demangled_name;
        std::free(demangled_name);
    }

    return name;
}

#endif

/* ---------------------------------------------------------------------------*/
/* Low Level Debugging                                                        */
/* ---------------------------------------------------------------------------*/

inline char *
bfitoa(size_t value, char *str, size_t base)
{
    const char digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    int i = 0, j = 0;
    size_t remainder;

    do {
        remainder = value % base;
        str[i++] = digits[remainder];
        value = value / base;
    }
    while (value != 0);

    str[i] = '\0';

    for (j = 0, i--; j < i; j++, i--) {
        char c = str[j];
        str[j] = str[i];
        str[i] = c;
    }

    return str;
}

#define CALLED() \
    { \
        const auto *str_text = "\033[1;32mDEBUG\033[0m: function called = "; \
        const auto *str_func = __BFFUNC__; \
        const auto *str_endl = "\n"; \
        unsafe_write_cstr(str_text, strlen(str_text)); \
        unsafe_write_cstr(str_func, strlen(str_func)); \
        unsafe_write_cstr(str_endl, strlen(str_endl)); \
    }

#define WARNING(a) \
    { \
        const auto *str_text = "\033[1;33mWARNING\033[0m: " a " = "; \
        const auto *str_func = __BFFUNC__; \
        const auto *str_endl = "\n"; \
        unsafe_write_cstr(str_text, strlen(str_text)); \
        unsafe_write_cstr(str_func, strlen(str_func)); \
        unsafe_write_cstr(str_endl, strlen(str_endl)); \
    }

#define UNHANDLED() \
    { \
        const auto *str_text = "\033[1;33mWARNING\033[0m: unsupported function called = "; \
        const auto *str_func = __BFFUNC__; \
        const auto *str_endl = "\n"; \
        unsafe_write_cstr(str_text, strlen(str_text)); \
        unsafe_write_cstr(str_func, strlen(str_func)); \
        unsafe_write_cstr(str_endl, strlen(str_endl)); \
    }

#define ARG_UNSUPPORTED(a) \
    { \
        const auto *str_text = "\033[1;33mWARNING\033[0m: " a " not supported for function called = "; \
        const auto *str_func = __BFFUNC__; \
        const auto *str_endl = "\n"; \
        unsafe_write_cstr(str_text, strlen(str_text)); \
        unsafe_write_cstr(str_func, strlen(str_func)); \
        unsafe_write_cstr(str_endl, strlen(str_endl)); \
    }


#define DEBUG_STR(a,b) \
    { \
        const auto *str_text = "\033[1;32mDEBUG\033[0m: " a " = "; \
        const auto *str_endl = "\n"; \
        unsafe_write_cstr(str_text, strlen(str_text)); \
        unsafe_write_cstr(b, strlen(b)); \
        unsafe_write_cstr(str_endl, strlen(str_endl)); \
    }

#define DEBUG_DEC(a,b) \
    { \
        char numstr[64]; \
        bfitoa(b, numstr, 10); \
        const auto *str_text = "\033[1;32mDEBUG\033[0m: " a " = "; \
        const auto *str_endl = "\n"; \
        unsafe_write_cstr(str_text, strlen(str_text)); \
        unsafe_write_cstr(numstr, strlen(numstr)); \
        unsafe_write_cstr(str_endl, strlen(str_endl)); \
    }

#define DEBUG_HEX(a,b) \
    { \
        char numstr[64]; \
        bfitoa(b, numstr, 16); \
        const auto *str_text = "\033[1;32mDEBUG\033[0m: " a " = "; \
        const auto *str_endl = "\n"; \
        unsafe_write_cstr(str_text, strlen(str_text)); \
        unsafe_write_cstr(numstr, strlen(numstr)); \
        unsafe_write_cstr(str_endl, strlen(str_endl)); \
    }

#define DEBUG_LINE() \
    { \
        char numstr[64]; \
        bfitoa(__LINE__, numstr, 10); \
        const auto *str_text = "\033[1;32mDEBUG\033[0m: "; \
        const auto *str_func = __BFFUNC__; \
        const auto *str_next = " = "; \
        const auto *str_endl = "\n"; \
        unsafe_write_cstr(str_text, strlen(str_text)); \
        unsafe_write_cstr(str_func, strlen(str_func)); \
        unsafe_write_cstr(str_next, strlen(str_next)); \
        unsafe_write_cstr(numstr, strlen(numstr)); \
        unsafe_write_cstr(str_endl, strlen(str_endl)); \
    }

/* ---------------------------------------------------------------------------*/
/* Helpers (Private)                                                          */
/* ---------------------------------------------------------------------------*/

inline std::size_t
__bfdebug_core(gsl::not_null<std::string *> msg)
{
    std::size_t digits = 1;

    *msg += bfcolor_cyan;
    *msg += "[";
    *msg += bfcolor_yellow;
#ifdef VMM
    digits = bfn::to_string(*msg, thread_context_cpuid(), 16, false);
#else
    *msg += '0';
#endif
    *msg += bfcolor_cyan;
    *msg += "] ";
    *msg += bfcolor_end;

    return digits;
}

inline void
__bfdebug_type(gsl::not_null<std::string *> msg, cstr_t color, cstr_t type)
{
    *msg += color;
    *msg += type;
    *msg += bfcolor_end;
    *msg += ": ";
}

inline void
__bfdebug_jtfy(gsl::not_null<std::string *> msg, int64_t width, cstr_t title, cstr_t indent)
{
    if (title != nullptr) {
        int64_t len = width - strlen(title);

        if (indent != nullptr) {
            len -= strlen(indent);
            *msg += indent;
        }

        *msg += title;

        for (int64_t i = 0; i < len; i++) {
            *msg += ' ';
        }
    }
    else {
        for (int64_t i = 0; i < width; i++) {
            *msg += ' ';
        }
    }
}

template<typename F>
void __bfdebug_transaction(F func)
{
    std::string msg;
    msg.reserve(0x1000);
    func(&msg);

#ifdef VMM
    write_str(msg);
#else
    std::cout << msg;
#endif
}

template<typename F>
void __bfdebug_add_line(std::string *msg, F func)
{
    if (msg == nullptr) {
        __bfdebug_transaction([&](std::string * tmsg) {
            func(tmsg);
        });
    }
    else {
        std::string ln;
        ln.reserve(0x1000);

        func(&ln);

        if (msg->size() + ln.size() > msg->capacity()) {
            msg->reserve(msg->capacity() + 0x1000);
        }

        *msg += ln;
    }
}

#define bfdebug_transaction(level,func)                                        \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_transaction(func);                                           \
    }

/* ---------------------------------------------------------------------------*/
/* Get Macro Magic                                                            */
/* ---------------------------------------------------------------------------*/

/*
 * This is a cleaned up version of the following:
 * https://stackoverflow.com/questions/11761703/overloading-macro-on-number-of-arguments
 *
 * This is needed because some of the debug macros only take a single argument,
 * which means __VA_ARGS__ gets mad because it's not used. For macros with more
 * than one arg, this is not needed. Also, if this becomes needed for other
 * things in the future, we should move this to it's own header
 *
 * The bug fix for MSVC comes from the following:
 * https://stackoverflow.com/questions/5134523/msvc-doesnt-expand-va-args-correctly
 */

#define __BUGFX(x) x

#define __NARG2(...) __BUGFX(__NARG1(__VA_ARGS__,__RSEQN()))
#define __NARG1(...) __BUGFX(__ARGSN(__VA_ARGS__))
#define __ARGSN(_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,N,...) N
#define __RSEQN() 10,9,8,7,6,5,4,3,2,1,0

#define __FUNC2(name,n) name ## n
#define __FUNC1(name,n) __FUNC2(name,n)
#define GET_MACRO(func,...) __FUNC1(func,__BUGFX(__NARG2(__VA_ARGS__))) (__VA_ARGS__)

/* ---------------------------------------------------------------------------*/
/* Info                                                                       */
/* ---------------------------------------------------------------------------*/

inline void
__bfdebug_info_core(cstr_t color, cstr_t type, cstr_t title, gsl::not_null<std::string *> msg)
{
    __bfdebug_core(msg);
    __bfdebug_type(msg, color, type);

    if (title != nullptr) {
        *msg += title;
    }

    *msg += '\n';
}

inline void
__bfdebug_info(cstr_t color, cstr_t type, cstr_t title, std::string *msg = nullptr)
{
    __bfdebug_add_line(msg, [&](std::string * ln) {
        __bfdebug_info_core(color, type, title, ln);
    });
}

#define bfdebug_info(level, ...)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_info(bfcolor_debug, "DEBUG", __VA_ARGS__);                   \
    }

#define bfalert_info(level, ...)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_info(bfcolor_alert, "ALERT", __VA_ARGS__);                   \
    }

#define bferror_info(level, ...)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_info(bfcolor_error, "ERROR", __VA_ARGS__);                   \
    }

/* ---------------------------------------------------------------------------*/
/* Line Break                                                                 */
/* ---------------------------------------------------------------------------*/

inline void
__bfdebug_lnbr_core(cstr_t color, cstr_t type, gsl::not_null<std::string *> msg)
{
    __bfdebug_core(msg);
    __bfdebug_type(msg, color, type);

    *msg += '\n';
}

inline void
__bfdebug_lnbr(cstr_t color, cstr_t type, std::string *msg = nullptr)
{
    __bfdebug_add_line(msg, [&](std::string * ln) {
        __bfdebug_lnbr_core(color, type, ln);
    });
}

#define bfdebug_lnbr1(level)                                                   \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_lnbr(bfcolor_debug, "DEBUG");                                \
    }

#define bfalert_lnbr1(level)                                                   \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_lnbr(bfcolor_alert, "ALERT");                                \
    }

#define bferror_lnbr1(level)                                                   \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_lnbr(bfcolor_error, "ERROR");                                \
    }

#define bfdebug_lnbr2(level,msg)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_lnbr(bfcolor_debug, "DEBUG", msg);                           \
    }

#define bfalert_lnbr2(level,msg)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_lnbr(bfcolor_alert, "ALERT", msg);                           \
    }

#define bferror_lnbr2(level,msg)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_lnbr(bfcolor_error, "ERROR", msg);                           \
    }

#define bfdebug_lnbr(...) GET_MACRO(bfdebug_lnbr, __VA_ARGS__)
#define bfalert_lnbr(...) GET_MACRO(bfalert_lnbr, __VA_ARGS__)
#define bferror_lnbr(...) GET_MACRO(bferror_lnbr, __VA_ARGS__)

/* ---------------------------------------------------------------------------*/
/* Horizontal Line Break1                                                     */
/* ---------------------------------------------------------------------------*/

inline void
__bfdebug_brk1_core(cstr_t color, cstr_t type, gsl::not_null<std::string *> msg)
{
    auto digits = __bfdebug_core(msg);
    __bfdebug_type(msg, color, type);

    for (auto i = 0; i < 70 - digits; i++) {
        *msg += '=';
    }

    *msg += '\n';
}

inline void
__bfdebug_brk1(cstr_t color, cstr_t type, std::string *msg = nullptr)
{
    __bfdebug_add_line(msg, [&](std::string * ln) {
        __bfdebug_brk1_core(color, type, ln);
    });
}

#define bfdebug_brk11(level)                                                   \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_brk1(bfcolor_debug, "DEBUG");                                \
    }

#define bfalert_brk11(level)                                                   \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_brk1(bfcolor_alert, "ALERT");                                \
    }

#define bferror_brk11(level)                                                   \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_brk1(bfcolor_error, "ERROR");                                \
    }

#define bfdebug_brk12(level,msg)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_brk1(bfcolor_debug, "DEBUG", msg);                           \
    }

#define bfalert_brk12(level,msg)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_brk1(bfcolor_alert, "ALERT", msg);                           \
    }

#define bferror_brk12(level,msg)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_brk1(bfcolor_error, "ERROR", msg);                           \
    }

#define bfdebug_brk1(...) GET_MACRO(bfdebug_brk1, __VA_ARGS__)
#define bfalert_brk1(...) GET_MACRO(bfalert_brk1, __VA_ARGS__)
#define bferror_brk1(...) GET_MACRO(bferror_brk1, __VA_ARGS__)

/* ---------------------------------------------------------------------------*/
/* Horizontal Line Break2                                                     */
/* ---------------------------------------------------------------------------*/

inline void
__bfdebug_brk2_core(cstr_t color, cstr_t type, gsl::not_null<std::string *> msg)
{
    auto digits = __bfdebug_core(msg);
    __bfdebug_type(msg, color, type);

    for (auto i = 0; i < 70 - digits; i++) {
        *msg += '-';
    }

    *msg += '\n';
}

inline void
__bfdebug_brk2(cstr_t color, cstr_t type, std::string *msg = nullptr)
{
    __bfdebug_add_line(msg, [&](std::string * ln) {
        __bfdebug_brk2_core(color, type, ln);
    });
}

#define bfdebug_brk21(level)                                                   \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_brk2(bfcolor_debug, "DEBUG");                                \
    }

#define bfalert_brk21(level)                                                   \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_brk2(bfcolor_alert, "ALERT");                                \
    }

#define bferror_brk21(level)                                                   \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_brk2(bfcolor_error, "ERROR");                                \
    }

#define bfdebug_brk22(level,msg)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_brk2(bfcolor_debug, "DEBUG", msg);                           \
    }

#define bfalert_brk22(level,msg)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_brk2(bfcolor_alert, "ALERT", msg);                           \
    }

#define bferror_brk22(level,msg)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_brk2(bfcolor_error, "ERROR", msg);                           \
    }

#define bfdebug_brk2(...) GET_MACRO(bfdebug_brk2, __VA_ARGS__)
#define bfalert_brk2(...) GET_MACRO(bfalert_brk2, __VA_ARGS__)
#define bferror_brk2(...) GET_MACRO(bferror_brk2, __VA_ARGS__)

/* ---------------------------------------------------------------------------*/
/* Horizontal Line Break3                                                     */
/* ---------------------------------------------------------------------------*/

inline void
__bfdebug_brk3_core(cstr_t color, cstr_t type, gsl::not_null<std::string *> msg)
{
    auto digits = __bfdebug_core(msg);
    __bfdebug_type(msg, color, type);

    for (auto i = 0; i < 70 - digits; i++) {
        *msg += '.';
    }

    *msg += '\n';
}

inline void
__bfdebug_brk3(cstr_t color, cstr_t type, std::string *msg = nullptr)
{
    __bfdebug_add_line(msg, [&](std::string * ln) {
        __bfdebug_brk3_core(color, type, ln);
    });
}

#define bfdebug_brk31(level)                                                   \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_brk3(bfcolor_debug, "DEBUG");                                \
    }

#define bfalert_brk31(level)                                                   \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_brk3(bfcolor_alert, "ALERT");                                \
    }

#define bferror_brk31(level)                                                   \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_brk3(bfcolor_error, "ERROR");                                \
    }

#define bfdebug_brk32(level,msg)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_brk3(bfcolor_debug, "DEBUG", msg);                           \
    }

#define bfalert_brk32(level,msg)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_brk3(bfcolor_alert, "ALERT", msg);                           \
    }

#define bferror_brk32(level,msg)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_brk3(bfcolor_error, "ERROR", msg);                           \
    }

#define bfdebug_brk3(...) GET_MACRO(bfdebug_brk3, __VA_ARGS__)
#define bfalert_brk3(...) GET_MACRO(bfalert_brk3, __VA_ARGS__)
#define bferror_brk3(...) GET_MACRO(bferror_brk3, __VA_ARGS__)

/* ---------------------------------------------------------------------------*/
/* Hex Number                                                                 */
/* ---------------------------------------------------------------------------*/

inline void
__bfdebug_nhex_core(
    cstr_t color, cstr_t type, cstr_t indent, cstr_t title, uint64_t nhex, gsl::not_null<std::string *> msg)
{
    auto digits = __bfdebug_core(msg);
    __bfdebug_type(msg, color, type);
    __bfdebug_jtfy(msg, 52 - digits, title, indent);

    bfn::to_string(*msg, nhex, 16);
    *msg += '\n';
}

inline void
__bfdebug_nhex(
    cstr_t color, cstr_t type, cstr_t indent, cstr_t title, uint64_t nhex, std::string *msg = nullptr)
{
    __bfdebug_add_line(msg, [&](std::string * ln) {
        __bfdebug_nhex_core(color, type, indent, title, nhex, ln);
    });
}

inline void
__bfdebug_nhex(
    cstr_t color, cstr_t type, cstr_t indent, cstr_t title, void *nhex, std::string *msg = nullptr)
{ __bfdebug_nhex(color, type, indent, title, reinterpret_cast<uint64_t>(nhex), msg); }

#define bfdebug_nhex(level, ...)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_nhex(bfcolor_debug, "DEBUG", nullptr, __VA_ARGS__);          \
    }

#define bfalert_nhex(level, ...)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_nhex(bfcolor_alert, "ALERT", nullptr, __VA_ARGS__);          \
    }

#define bferror_nhex(level, ...)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_nhex(bfcolor_error, "ERROR", nullptr, __VA_ARGS__);          \
    }

#define bfdebug_subnhex(level, ...)                                            \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_nhex(bfcolor_debug, "DEBUG", "  - ", __VA_ARGS__);           \
    }

#define bfalert_subnhex(level, ...)                                            \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_nhex(bfcolor_alert, "ALERT", "  - ", __VA_ARGS__);           \
    }

#define bferror_subnhex(level, ...)                                            \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_nhex(bfcolor_error, "ERROR", "  - ", __VA_ARGS__);           \
    }

/* ---------------------------------------------------------------------------*/
/* Decimal Number                                                             */
/* ---------------------------------------------------------------------------*/

inline void
__bfdebug_ndec_core(
    cstr_t color, cstr_t type, cstr_t indent, cstr_t title, uint64_t ndec, gsl::not_null<std::string *> msg)
{
    auto digits = __bfdebug_core(msg);
    __bfdebug_type(msg, color, type);
    __bfdebug_jtfy(msg, 70 - digits - bfn::digits(ndec), title, indent);

    bfn::to_string(*msg, ndec);
    *msg += '\n';
}

inline void
__bfdebug_ndec(
    cstr_t color, cstr_t type, cstr_t indent, cstr_t title, uint64_t ndec, std::string *msg = nullptr)
{
    __bfdebug_add_line(msg, [&](std::string * ln) {
        __bfdebug_ndec_core(color, type, indent, title, ndec, ln);
    });
}

#define bfdebug_ndec(level, ...)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_ndec(bfcolor_debug, "DEBUG", nullptr, __VA_ARGS__);          \
    }

#define bfalert_ndec(level, ...)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_ndec(bfcolor_alert, "ALERT", nullptr, __VA_ARGS__);          \
    }

#define bferror_ndec(level, ...)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_ndec(bfcolor_error, "ERROR", nullptr, __VA_ARGS__);          \
    }

#define bfdebug_subndec(level, ...)                                            \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_ndec(bfcolor_debug, "DEBUG", "  - ", __VA_ARGS__);           \
    }

#define bfalert_subndec(level, ...)                                            \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_ndec(bfcolor_alert, "ALERT", "  - ", __VA_ARGS__);           \
    }

#define bferror_subndec(level, ...)                                            \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_ndec(bfcolor_error, "ERROR", "  - ", __VA_ARGS__);           \
    }

/* ---------------------------------------------------------------------------*/
/* Boolean                                                                    */
/* ---------------------------------------------------------------------------*/

inline void
__bfdebug_bool_core(
    cstr_t color, cstr_t type, cstr_t indent, cstr_t title, bool val, gsl::not_null<std::string *> msg)
{
    auto str = val ? "true" : "false";

    auto digits = __bfdebug_core(msg);
    __bfdebug_type(msg, color, type);
    __bfdebug_jtfy(msg, 70 - strlen(str) - digits, title, indent);

    *msg += str;
    *msg += '\n';
}

inline void
__bfdebug_bool(
    cstr_t color, cstr_t type, cstr_t indent, cstr_t title, bool val, std::string *msg = nullptr)
{
    __bfdebug_add_line(msg, [&](std::string * ln) {
        __bfdebug_bool_core(color, type, indent, title, val, ln);
    });
}

#define bfdebug_bool(level, ...)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_bool(bfcolor_debug, "DEBUG", nullptr, __VA_ARGS__);          \
    }

#define bfalert_bool(level, ...)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_bool(bfcolor_alert, "ALERT", nullptr, __VA_ARGS__);          \
    }

#define bferror_bool(level, ...)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_bool(bfcolor_error, "ERROR", nullptr, __VA_ARGS__);          \
    }

#define bfdebug_subbool(level, ...)                                            \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_bool(bfcolor_debug, "DEBUG", "  - ", __VA_ARGS__);           \
    }

#define bfalert_subbool(level, ...)                                            \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_bool(bfcolor_alert, "ALERT", "  - ", __VA_ARGS__);           \
    }

#define bferror_subbool(level, ...)                                            \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_bool(bfcolor_error, "ERROR", "  - ", __VA_ARGS__);           \
    }

/* ---------------------------------------------------------------------------*/
/* Text                                                                       */
/* ---------------------------------------------------------------------------*/

inline void
__bfdebug_text_core(
    cstr_t color, cstr_t type, cstr_t indent, cstr_t title, cstr_t text, gsl::not_null<std::string *> msg)
{
    auto str = text == nullptr ? "" : text;

    auto digits = __bfdebug_core(msg);
    __bfdebug_type(msg, color, type);
    __bfdebug_jtfy(msg, 70 - strlen(str) - digits, title, indent);

    *msg += str;
    *msg += '\n';
}

inline void
__bfdebug_text(
    cstr_t color, cstr_t type, cstr_t indent, cstr_t title, cstr_t text, std::string *msg = nullptr)
{
    __bfdebug_add_line(msg, [&](std::string * ln) {
        __bfdebug_text_core(color, type, indent, title, text, ln);
    });
}

#define bfdebug_text(level, ...)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_text(bfcolor_debug, "DEBUG", nullptr, __VA_ARGS__);          \
    }

#define bfalert_text(level, ...)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_text(bfcolor_alert, "ALERT", nullptr, __VA_ARGS__);          \
    }

#define bferror_text(level, ...)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_text(bfcolor_error, "ERROR", nullptr, __VA_ARGS__);          \
    }

#define bfdebug_subtext(level, ...)                                            \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_text(bfcolor_debug, "DEBUG", "  - ", __VA_ARGS__);           \
    }

#define bfalert_subtext(level, ...)                                            \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_text(bfcolor_alert, "ALERT", "  - ", __VA_ARGS__);           \
    }

#define bferror_subtext(level, ...)                                            \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_text(bfcolor_error, "ERROR", "  - ", __VA_ARGS__);           \
    }

/* ---------------------------------------------------------------------------*/
/* Pass                                                                       */
/* ---------------------------------------------------------------------------*/

inline void
__bfdebug_pass_core(
    cstr_t color, cstr_t type, cstr_t indent, cstr_t title, gsl::not_null<std::string *> msg)
{
    auto digits = __bfdebug_core(msg);
    __bfdebug_type(msg, color, type);
    __bfdebug_jtfy(msg, 66 - digits, title, indent);

    *msg += bfcolor_green "pass" bfcolor_end;
    *msg += '\n';
}

inline void
__bfdebug_pass(
    cstr_t color, cstr_t type, cstr_t indent, cstr_t title, std::string *msg = nullptr)
{
    __bfdebug_add_line(msg, [&](std::string * ln) {
        __bfdebug_pass_core(color, type, indent, title, ln);
    });
}

#define bfdebug_pass(level, ...)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_pass(bfcolor_debug, "DEBUG", nullptr, __VA_ARGS__);          \
    }

#define bfalert_pass(level, ...)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_pass(bfcolor_alert, "ALERT", nullptr, __VA_ARGS__);          \
    }

#define bferror_pass(level, ...)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_pass(bfcolor_error, "ERROR", nullptr, __VA_ARGS__);          \
    }

#define bfdebug_subpass(level, ...)                                            \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_pass(bfcolor_debug, "DEBUG", "  - ", __VA_ARGS__);           \
    }

#define bfalert_subpass(level, ...)                                            \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_pass(bfcolor_alert, "ALERT", "  - ", __VA_ARGS__);           \
    }

#define bferror_subpass(level, ...)                                            \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_pass(bfcolor_error, "ERROR", "  - ", __VA_ARGS__);           \
    }

/* ---------------------------------------------------------------------------*/
/* Fail                                                                       */
/* ---------------------------------------------------------------------------*/

inline void
__bfdebug_fail_core(
    cstr_t color, cstr_t type, cstr_t indent, cstr_t title, gsl::not_null<std::string *> msg)
{
    auto digits = __bfdebug_core(msg);
    __bfdebug_type(msg, color, type);
    __bfdebug_jtfy(msg, 66 - digits, title, indent);

    *msg += bfcolor_red "fail  <----" bfcolor_end;
    *msg += '\n';
}

inline void
__bfdebug_fail(
    cstr_t color, cstr_t type, cstr_t indent, cstr_t title, std::string *msg = nullptr)
{
    __bfdebug_add_line(msg, [&](std::string * ln) {
        __bfdebug_fail_core(color, type, indent, title, ln);
    });
}

#define bfdebug_fail(level, ...)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_fail(bfcolor_debug, "DEBUG", nullptr, __VA_ARGS__);          \
    }

#define bfalert_fail(level, ...)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_fail(bfcolor_alert, "ALERT", nullptr, __VA_ARGS__);          \
    }

#define bferror_fail(level, ...)                                               \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_fail(bfcolor_error, "ERROR", nullptr, __VA_ARGS__);          \
    }

#define bfdebug_subfail(level, ...)                                            \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_fail(bfcolor_debug, "DEBUG", "  - ", __VA_ARGS__);           \
    }

#define bfalert_subfail(level, ...)                                            \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_fail(bfcolor_alert, "ALERT", "  - ", __VA_ARGS__);           \
    }

#define bferror_subfail(level, ...)                                            \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        __bfdebug_fail(bfcolor_error, "ERROR", "  - ", __VA_ARGS__);           \
    }

/* ---------------------------------------------------------------------------*/
/* Test                                                                       */
/* ---------------------------------------------------------------------------*/

#define bfdebug_test3(level,title,val)                                         \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        if ((val)) {                                                           \
            bfdebug_pass(level,title);                                         \
        }                                                                      \
        else {                                                                 \
            bfdebug_fail(level,title);                                         \
        }                                                                      \
    }

#define bfdebug_subtest3(level,title,val)                                      \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        if ((val)) {                                                           \
            bfdebug_subpass(level,title);                                      \
        }                                                                      \
        else {                                                                 \
            bfdebug_subfail(level,title);                                      \
        }                                                                      \
    }

#define bfalert_test3(level,title,val)                                         \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        if ((val)) {                                                           \
            bfalert_pass(level,title);                                         \
        }                                                                      \
        else {                                                                 \
            bfalert_fail(level,title);                                         \
        }                                                                      \
    }

#define bfalert_subtest3(level,title,val)                                      \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        if ((val)) {                                                           \
            bfalert_subpass(level,title);                                      \
        }                                                                      \
        else {                                                                 \
            bfalert_subfail(level,title);                                      \
        }                                                                      \
    }

#define bferror_test3(level,title,val)                                         \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        if ((val)) {                                                           \
            bferror_pass(level,title);                                         \
        }                                                                      \
        else {                                                                 \
            bferror_fail(level,title);                                         \
        }                                                                      \
    }

#define bferror_subtest3(level,title,val)                                      \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        if ((val)) {                                                           \
            bferror_subpass(level,title);                                      \
        }                                                                      \
        else {                                                                 \
            bferror_subfail(level,title);                                      \
        }                                                                      \
    }

#define bfdebug_test4(level,title,val,msg)                                     \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        if ((val)) {                                                           \
            bfdebug_pass(level,title,msg);                                     \
        }                                                                      \
        else {                                                                 \
            bfdebug_fail(level,title,msg);                                     \
        }                                                                      \
    }

#define bfdebug_subtest4(level,title,val,msg)                                  \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        if ((val)) {                                                           \
            bfdebug_subpass(level,title,msg);                                  \
        }                                                                      \
        else {                                                                 \
            bfdebug_subfail(level,title,msg);                                  \
        }                                                                      \
    }

#define bfalert_test4(level,title,val,msg)                                     \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        if ((val)) {                                                           \
            bfalert_pass(level,title,msg);                                     \
        }                                                                      \
        else {                                                                 \
            bfalert_fail(level,title,msg);                                     \
        }                                                                      \
    }

#define bfalert_subtest4(level,title,val,msg)                                  \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        if ((val)) {                                                           \
            bfalert_subpass(level,title,msg);                                  \
        }                                                                      \
        else {                                                                 \
            bfalert_subfail(level,title,msg);                                  \
        }                                                                      \
    }

#define bferror_test4(level,title,val,msg)                                     \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        if ((val)) {                                                           \
            bferror_pass(level,title,msg);                                     \
        }                                                                      \
        else {                                                                 \
            bferror_fail(level,title,msg);                                     \
        }                                                                      \
    }

#define bferror_subtest4(level,title,val,msg)                                  \
    if (GSL_UNLIKELY(level <= DEBUG_LEVEL)) {                                  \
        if ((val)) {                                                           \
            bferror_subpass(level,title,msg);                                  \
        }                                                                      \
        else {                                                                 \
            bferror_subfail(level,title,msg);                                  \
        }                                                                      \
    }

#define bfdebug_test(...) GET_MACRO(bfdebug_test, __VA_ARGS__)
#define bfdebug_subtest(...) GET_MACRO(bfdebug_subtest, __VA_ARGS__)
#define bfalert_test(...) GET_MACRO(bfalert_test, __VA_ARGS__)
#define bfalert_subtest(...) GET_MACRO(bfalert_subtest, __VA_ARGS__)
#define bferror_test(...) GET_MACRO(bferror_test, __VA_ARGS__)
#define bferror_subtest(...) GET_MACRO(bferror_subtest, __VA_ARGS__)

/* ---------------------------------------------------------------------------*/
/* Exception                                                                  */
/* ---------------------------------------------------------------------------*/

inline void
bfdebug_exception()
{
    bfdebug_transaction(0, [&](std::string * msg) {
        bferror_lnbr(0, msg);
        bferror_brk1(0, msg);
        bferror_info(0, "unknown exception", msg);
        bferror_brk1(0, msg);
        bferror_lnbr(0, msg);
    });
}

inline void
bfdebug_exception(const std::exception &e)
{
    bfdebug_transaction(0, [&](std::string * msg) {
        bferror_lnbr(0, msg);
        bferror_brk1(0, msg);
        bferror_info(0, type_name(e).c_str(), msg);
        bferror_brk1(0, msg);
        bferror_info(0, e.what(), msg);
        bferror_lnbr(0, msg);
    });
}

#define catchall(a)                                                             \
    catch (std::bad_alloc &) {                                                  \
        a;                                                                      \
    }                                                                           \
    catch (std::exception &e) {                                                 \
        bfdebug_exception(e);                                                   \
        a;                                                                      \
    }                                                                           \
    catch (...) {                                                               \
        bfdebug_exception();                                                    \
        a;                                                                      \
    }

/* ---------------------------------------------------------------------------*/
/* Line / Field                                                               */
/* ---------------------------------------------------------------------------*/

#define bfline bfdebug_ndec(0, "line", __LINE__);
#define __bffield1(a,b) bfdebug_ndec(0, "[" #b "] " #a, a);
#define __bffield2(a,b) __bffield1(a,b);
#define bffield(a) __bffield2(a,__LINE__)
#define __bffield_hex1(a,b) bfdebug_nhex(0, "[" #b "] " #a, a);
#define __bffield_hex2(a,b) __bffield_hex1(a,b);
#define bffield_hex(a) __bffield_hex2(a,__LINE__)

#endif

/* -------------------------------------------------------------------------- */
/* C Debugging                                                                */
/* -------------------------------------------------------------------------- */

#if !defined(KERNEL) && !defined(EFI)
#ifdef __cplusplus
#include <cstdio>
#else
#include <stdio.h>
#endif
#define BFINFO(...) printf(__VA_ARGS__)
#define BFDEBUG(...) printf("[BAREFLANK DEBUG]: " __VA_ARGS__)
#define BFALERT(...) printf("[BAREFLANK ALERT]: " __VA_ARGS__)
#define BFERROR(...) printf("[BAREFLANK ERROR]: " __VA_ARGS__)
#endif

/* -------------------------------------------------------------------------- */
/* Linux Debugging                                                            */
/* -------------------------------------------------------------------------- */

#if defined(KERNEL) && !defined(EFI)
#ifdef __linux__
#include <linux/printk.h>
#define BFINFO(...) printk(KERN_INFO __VA_ARGS__)
#define BFDEBUG(...) printk(KERN_INFO "[BAREFLANK DEBUG]: " __VA_ARGS__)
#define BFALERT(...) printk(KERN_INFO "[BAREFLANK ALERT]: " __VA_ARGS__)
#define BFERROR(...) printk(KERN_ALERT "[BAREFLANK ERROR]: " __VA_ARGS__)
#endif
#endif

/* -------------------------------------------------------------------------- */
/* Windows Debugging                                                          */
/* -------------------------------------------------------------------------- */

#if defined(KERNEL) && !defined(EFI)
#ifdef _WIN32
#include <wdm.h>
#define BFINFO(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, __VA_ARGS__)
#define BFDEBUG(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[BAREFLANK DEBUG]: " __VA_ARGS__)
#define BFALERT(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[BAREFLANK ALERT]: " __VA_ARGS__)
#define BFERROR(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[BAREFLANK ERROR]: " __VA_ARGS__)
#endif
#endif

/* -------------------------------------------------------------------------- */
/* EFI Debugging                                                              */
/* -------------------------------------------------------------------------- */

#if defined(KERNEL) && defined(EFI)
#include "efi.h"
#include "efilib.h"
#define BFINFO(...) Print(L__VA_ARGS__)
#define BFDEBUG(...) Print(L"[BAREFLANK DEBUG]: " __VA_ARGS__)
#define BFALERT(...) Print(L"[BAREFLANK ALERT]: " __VA_ARGS__)
#define BFERROR(...) Print(L"[BAREFLANK ERROR]: " __VA_ARGS__)
#endif

/** @endcond */

#endif
