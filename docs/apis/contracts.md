## **Contracts**

Contracts provides a way to define preconditions, postconditions and assertions. The BSL provides an implementation of contracts based on the following:

http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2018/p0542r5.html

##### example:
``` c++
{!examples/contracts/general_usage.cpp!}
```

!!! note "Configuration Macros"

    ??? summary "BSL_BUILD_LEVEL"

        Defines which types of contracts are checked (defaults to 1):

        -   0: off, no contracts are checked.
        -   1: default, default contracts are checked.
        -   2: audit, default and audit contracts are checked.

    ??? summary "BSL_CONTINUE_OPTION"

        Defines whether or not contract violations should continue after their          execution. Note that the default violation handler executes
        `#!c++ std::abort()` as per the spec. Therefore, if you want a contract
        violation to continue its execution, you must also provide a custom
        violation handle that safely returns (defaults to 0).

        -   0: off, unhandled contract violations result in
            `#!c++ std::abort()` being called.
        -   1: on, unhandled contract violations are ignored.

### **Functions**

- [expects](#contracts__expects)
- [ensures](#contracts__ensures)
- [assert](#contracts__assert)

#### Audit Contracts
- [expects_audit](#contracts__expects_audit)
- [ensures_audit](#contracts__ensures_audit)
- [assert_audit](#contracts__assert_audit)

#### Axiom Contracts
- [expects_axiom](#contracts__expects_axiom)
- [ensures_axiom](#contracts__ensures_axiom)
- [assert_axiom](#contracts__assert_axiom)

#### Configuration
- [set_violation_handler](#contracts__set_violation_handler)

---

<h3 id="contracts__expects">
expects
</h3>

``` c++
auto
expects(bool test) -> void
```

Checks the preconditions of a function. If the precondition evaluates to false, the violation handler is executed if the BSL_BUILD_LEVEL is set to 1 or 2, otherwise it is ignored. Execution will only continue if a custom violation handler is provided using set_violation_handler(), and BSL_CONTINUE_OPTION is enabled, otherwise execution will halt.

??? note "Parameters"

    ??? summary "test"

        The precondition to evaluate

??? note "Return"
    Not applicable

##### example:
``` c++
{!examples/contracts/expects.cpp!}
```

---

<h3 id="contracts__ensures">
ensures
</h3>

``` c++
auto
ensures(bool test) -> void
```

Checks the postconditions of a function. If the postcondition evaluates to false, the violation handler is executed if the BSL_BUILD_LEVEL is set to 1 or 2, otherwise it is ignored. Execution will only continue if a custom violation handler is provided using set_violation_handler(), and BSL_CONTINUE_OPTION is enabled, otherwise execution will halt.

??? note "Parameters"

    ??? summary "test"

        The postcondition to evaluate

??? note "Return"
    Not applicable

##### example:
``` c++
{!examples/contracts/ensures.cpp!}
```

---

<h3 id="contracts__assert">
assert
</h3>

``` c++
auto
assert(bool test) -> void
```

Checks an assertion at any location within a function. If the assertion evaluates to false, the violation handler is executed if the BSL_BUILD_LEVEL is set to 1 or 2, otherwise it is ignored. Execution will only continue if a custom violation handler is provided using set_violation_handler(), and BSL_CONTINUE_OPTION is enabled, otherwise execution will halt.

??? note "Parameters"

    ??? summary "test"

        The assertion to evaluate

??? note "Return"
    Not applicable

##### example:
``` c++
{!examples/contracts/assert.cpp!}
```

---

<h3 id="contracts__expects_audit">
expects_audit
</h3>

``` c++
auto
expects_audit(bool test) -> void
```

Checks the preconditions of a function. If the precondition evaluates to false, the violation handler is executed if the BSL_BUILD_LEVEL is set to 2, otherwise it is ignored. Execution will only continue if a custom violation handler is provided using set_violation_handler(), and BSL_CONTINUE_OPTION is enabled, otherwise execution will halt.

??? note "Parameters"

    ??? summary "test"

        The precondition to evaluate

??? note "Return"
    Not applicable

##### example:
``` c++
{!examples/contracts/expects_audit.cpp!}
```

---

<h3 id="contracts__ensures_audit">
ensures_audit
</h3>

``` c++
auto
ensures_audit(bool test) -> void
```

Checks the postconditions of a function. If the postcondition evaluates to false, the violation handler is executed if the BSL_BUILD_LEVEL is set to 1, otherwise it is ignored. Execution will only continue if a custom violation handler is provided using set_violation_handler(), and BSL_CONTINUE_OPTION is enabled, otherwise execution will halt.

??? note "Parameters"

    ??? summary "test"

        The postcondition to evaluate

??? note "Return"
    Not applicable

##### example:
``` c++
{!examples/contracts/ensures_audit.cpp!}
```

---

<h3 id="contracts__assert_audit">
assert_audit
</h3>

``` c++
auto
assert_audit(bool test) -> void
```

Checks an assertion at any location within a function. If the assertion evaluates to false, the violation handler is executed if the BSL_BUILD_LEVEL is set to 1, otherwise it is ignored. Execution will only continue if a custom violation handler is provided using set_violation_handler(), and BSL_CONTINUE_OPTION is enabled, otherwise execution will halt.

??? note "Parameters"

    ??? summary "test"

        The assertion to evaluate

??? note "Return"
    Not applicable

##### example:
``` c++
{!examples/contracts/assert_audit.cpp!}
```

---

<h3 id="contracts__expects_axiom">
expects_axiom
</h3>

``` c++
auto
expects_axiom(bool test) -> void
```

Checks the preconditions of a function. If the precondition evaluates to false, the violation is always ignored. Axioms exist to document the a contract only.

??? note "Parameters"

    ??? summary "test"

        The precondition to evaluate

??? note "Return"
    Not applicable

##### example:
``` c++
{!examples/contracts/expects_axiom.cpp!}
```

---

<h3 id="contracts__ensures_axiom">
ensures_axiom
</h3>

``` c++
auto
ensures_axiom(bool test) -> void
```

Checks the postconditions of a function. If the postcondition evaluates to false, the violation is always ignored. Axioms exist to document the a contract only.

??? note "Parameters"

    ??? summary "test"

        The postcondition to evaluate

??? note "Return"
    Not applicable

##### example:
``` c++
{!examples/contracts/ensures_axiom.cpp!}
```

---

<h3 id="contracts__assert_axiom">
assert_axiom
</h3>

``` c++
auto
assert_axiom(bool test) -> void
```

Checks an assertion at any location within a function. If the assertion evaluates to false, the violation is always ignored. Axioms exist to document the a contract only.

??? note "Parameters"

    ??? summary "test"

        The assertion to evaluate

??? note "Return"
    Not applicable

##### example:
``` c++
{!examples/contracts/assert_axiom.cpp!}
```

---

<h3 id="contracts__set_violation_handler">
set_violation_handler
</h3>

``` c++
constexpr auto
set_violation_handler(void (*handler)(const violation_info &)) noexcept -> void
```

Sets the current violation handler. The provided function will be called when a contract violation is detected instead of calling the default violation handler. When called, the violation handler will be given an l-value reference to the following violation information:

``` c++
struct violation_info
{
    source_location location;
    const char *comment;
};
```

??? note "Parameters"

    ??? summary "handler"

        A pointer to the violation handler to use instead of the default                violation handler

??? note "Return"
    Not applicable

##### example:
``` c++
{!examples/contracts/set_violation_handler.cpp!}
```

---
