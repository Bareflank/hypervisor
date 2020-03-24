## **Dynamic Array**

The C++ Standard Library currently does not have support for dynamic arrays. The best options are:

- `#!c++ std::vector`
- `#!c++ std::unique_ptr`

The `#!c++ std::vector` is likely the best option, with the downside that there is no ability to control the size of the internal memory that a `#!c++ std::vector` creates (the count based constructors only state the minimum size a `#!c++ std::vector` allocates, not the actual size), and a `#!c++ std::vector` will always value-initialize the memory it allocates. When working with really large buffers, this can be problematic. The `#!c++ std::vector` can also be copied, which could lead to accidental copies when moves are intended.
Finally, the `#!c++ std::vector` uses the allocator model, which is not well
suited for mapping operations (like mapping in memory or files).

The `#!c++ std::unique_ptr` has an array type, and solves most of the above problems, but it is not Core Guideline Compliant, does not store the size of the array you allocate, and does not provide support for iterators, or other types of accessors like `#!c++ at()`.

The BSL dynamic array is modeled after the `#!c++ std::unique_ptr` with the following changes:

- The size of the array is stored along with the pointer. Empty base optimizations are still leveraged to ensure the minimal possible storage requirements (similar to a `#!c++ std::unique_ptr`).
- The deleter is given both the pointer and the size, providing support for `#!c++ free()` and `#!c++ unmap()` style functions that require both the pointer and the size without the deleter having to duplicate this storage.
- Iterators are provided (random access), including support for ranged based for-loops.
- Accessors like `#!c++ front()`, `#!c++ back()`, `#!c++ []` and `#!c++ at()` are provided along with some other convenience functions.
- Core Guideline compliance is an optional feature that can be enabled to ensure out-of-range errors are detectable.

Our hope with this class is that it eliminates the need for a `#!c++ gsl::span` as currently, the main use case we have for a `#!c++ gsl::span` is when array types are allocated using `#!c++ std::unique_ptr` as most Standard Library containers already provide Core Guideline compliant mechanisms for accessing their contents.

??? todo

    - [ ] Add support for reference and pointer style Deleters
    - [ ] Add support for the >, <, >= and <= operators
    - [ ] Add support for some missing `#!c++ gsl::span` constructors and
          helper style functions like `#!c++ subspan()` so that if a
          `#!c++ gsl::span` is needed, this class can be used in its place
          using the nodelete Deleter.
    - [ ] Add some additional fill() functions (an operator=() versions) to
          make it easier to work with the array.

??? note "Template Parameters"

    ??? summary "T"
        The element type to store in the `#!c++ bsl::dynarray`. There are               little to no restrictions on what type T can be.

    ??? summary "Deleter"
        The deleter type the `#!c++ bsl::dynarray` should use to delete the
        array when the `#!c++ bsl::dynarray` loses scope. By default, the
        `#!c++ bsl::dynarray` provides a default deleter that calls
        `#!c++ delete []`. If a custom deleter is provided, it will be
        default constructed unless one of the l-value or r-value constructors
        are used to pass in a non-default constructed deleter. The requirements
        for the deleter depend on which constructor is used, but in general,
        the deleter should be nothrow movable.

        !!! warning
            We currently do not support reference or pointer Deleter types.

??? note "Member Types"

    !!! summary "value_type = T"
    !!! summary "element_type = T"
    !!! summary "index_type = std::size_t"
    !!! summary "difference_type = std::ptrdiff_t"
    !!! summary "reference = T &"
    !!! summary "const_reference = const T &"
    !!! summary "pointer = T *"
    !!! summary "const_pointer = const T *"
    !!! summary "deleter_type = Deleter"
    !!! summary "const_deleter_type = const Deleter"
    !!! summary "iterator = random_access_iterator"
    !!! summary "const_iterator = random_access_iterator"
    !!! summary "reverse_iterator = std::reverse_iterator"
    !!! summary "const_reverse_iterator = std::reverse_iterator"

### **Member Functions**

- [default constructor](#dynarray__default_constructor)
- [explicit constructors](#dynarray__explicit_constructors)
- [move constructor](#dynarray__move_constructor)
- [destructor](#dynarray__destructor)
#### Assignment
- [move assignment](#dynarray__move_assignment)
#### Modifiers:
- [release](#dynarray__release)
- [reset](#dynarray__reset)
- [swap](#dynarray__swap)
#### Observers:
- [get](#dynarray__get)
- [get_deleter](#dynarray__get_deleter)
- [operator bool](#dynarray__operator_bool)
#### Element Access:
- [operator\[\]](#dynarray__operator_subscript)
- [at](#dynarray__at)
- [front](#dynarray__front)
- [back](#dynarray__back)
- [data](#dynarray__data)
#### Iterators:
- [begin / cbegin](#dynarray__begin_cbegin)
- [end / cend](#dynarray__end_cend)
- [rbegin / crbegin](#dynarray__rbegin_crbegin)
- [rend / crend](#dynarray__rend_crend)
#### Capacity:
- [empty](#dynarray__empty)
- [size / ssize](#dynarray__size_ssize)
- [size_bytes](#dynarray__size_bytes)
- [max_size](#dynarray__max_size)
#### Operations:
- [fill](#dynarray__fill)

### **Non-Member Functions**

- [make_dynarray](#dynarray__make_dynarray)
- [make_dynarray_default_init](#dynarray__make_dynarray_default_init)
- [operator== / operator!=](#dynarray__operator_comparison_equals)
- [operator<<](#dynarray__operator_ostream)

---

<h3 id="dynarray__default_constructor">
default constructor
</h3>

``` c++
constexpr dynarray() noexcept;
```

Creates a default initialized `#!c++ bsl::dynarray`. When called, `#!c++ get()` will return a null pointer, and `#!c++ size()` will return 0.

??? note "Parameters"
    Not applicable

??? note "Return"
    Not applicable

??? note "Contracts"

    ??? summary "Expects"
        - None

    ??? summary "Ensures"
        - `#!c++ empty()` == true

!!! example "Usage"

    ``` c++
    auto a = bsl::dynarray<int>();
    ```

---

<h3 id="dynarray__explicit_constructors">
explicit constructors
</h3>

``` c++
explicit dynarray(
    pointer ptr, index_type count) BSL_NOEXCEPT;

explicit dynarray(
    pointer ptr, index_type count, const deleter_type &d) BSL_NOEXCEPT;

explicit dynarray(
    pointer ptr, index_type count, deleter_type &&d) BSL_NOEXCEPT;
```

Creates a value initialized `#!c++ bsl::dynarray` that owns an array at ptr, of count elements of T. When called, `#!c++ get()` will return ptr and `#!c++ size()` will return count. Unless a Deleter is also provided (either l-value or r-value), the Deleter is initialized using value-initialization (i.e., `#!c++ Deleter()`).

??? note "Parameters"

    ??? summary "ptr"
        a pointer to the array (a continuous memory block) the
        `#!c++ bsl::dynarray` will manage. If the default deleter is used,
        this memory must be allocated using the `#!c++ new []` operator.

    ??? summary "count"
        the number of elements in the array.

        !!! warning "Note"
            the count does not refer to the number of bytes, but rather the                 total number of elements.

    ??? summary "deleter (optional)"
        an l-value or r-value reference to a custom deleter. The
        `#!c++ bsl::dynarray` will create a copy of this deleter and use it to
        delete the pointer when the `#!c++ bsl::dynarray` loses scope.

??? note "Return"
    Not applicable

??? note "Contracts"

    ??? summary "Expects"
        - `#!c++ ptr` must not be a null pointer
        - `#!c++ count` must be larger than 0.

    ??? summary "Ensures"
        - `#!c++ empty()` == false

!!! example "Usage"

    ``` c++
    auto d = Deleter();

    auto a1 = bsl::dynarray<int>(new int[1], 1);
    auto a2 = bsl::dynarray<int>(new int[1], 1, d);
    auto a3 = bsl::dynarray<int>(new int[1], 1, Deleter());
    ```

!!! warning
    This function will throw when both BSL_CORE_GUIDELINE_COMPLIANT
    and BSL_THROW_ON_CONTRACT_VIOLATION are defined prior to including
    the BSL when a contract violation occurs. Otherwise, this function will
    call `#!c++ std::terminate()` on such violations.

---

<h3 id="dynarray__move_constructor">
move constructor
</h3>

``` c++
explicit dynarray(dynarray &&u) noexcept
```

Creates a `#!c++ bsl::dynarray` from another `#!c++ bsl::dynarray` using move semantics. This constructor ensures that `#!c++ u.empty()` is true. Whether or not the newly constructed `#!c++ bsl::dynarray` is empty depends on whether or not `#!c++ u` is empty at the time of the move.

??? note "Parameters"

    ??? summary "u"
        a `#!c++ bsl::dynarray` to construct a new `#!c++ bsl::dynarray` from.

??? note "Return"
    Not applicable

??? note "Contracts"

    ??? summary "Expects"
        - None

    ??? summary "Ensures"
        - `#!c++ u.empty()` == true

!!! example "Usage"

    ``` c++
    auto a1 = bsl::make_dynarray<int>(1);
    auto a2 = bsl::dynarray<int>(std::move(a1));
    ```

---

<h3 id="dynarray__destructor">
~dynarray()
</h3>

``` c++
~dynarray()
```

If the `#!c++ bsl::dynarray` is valid (i.e., `#!c++ get()` does not return a null pointer), the destructor will use the deleter to delete the array that it owns. Otherwise, this function has no affect.

??? note "Parameters"
    Not applicable

??? note "Return"
    Not applicable

??? note "Contracts"

    ??? summary "Expects"
        - None

    ??? summary "Ensures"
        - None

---

<h3 id="dynarray__move_assignment">
move assignment
</h3>

``` c++
constexpr auto
operator=(dynarray &&r) noexcept -> dynarray &
```

Transfers ownership of a `#!c++ bsl::dynarray` to this `#!c++ bsl::dynarray` using move semantics. This assignment ensures that `#!c++ r.empty()` is true. Whether or not the this `#!c++ bsl::dynarray` is empty depends on whether or not `#!c++ r` is empty at the time of the move. If this `#!c++ bsl::dynarray` already owns an array, it will be deleted before the move takes place.

??? note "Parameters"

    ??? summary "r"
        a `#!c++ bsl::dynarray` to transfer ownership from.

??? note "Return"
    `#!c++ *this`

??? note "Contracts"

    ??? summary "Expects"
        - None

    ??? summary "Ensures"
        - `#!c++ r.empty()` == true

!!! example "Usage"

    ``` c++
    auto a1 = bsl::make_dynarray<int>(1);
    auto a2 = bsl::make_dynarray<int>(1);
    a2 = std::move(a1);
    ```

---

<h3 id="dynarray__release">
release
</h3>

``` c++
[[nodiscard]] constexpr auto
release() noexcept -> std::pair<pointer, index_type>
```

Transfers ownership of a `#!c++ bsl::dynarray` to the caller by returning a pointer to the array and the number of elements in the array. After the execution of this function, `#!c++ get()` will return a null pointer and `#!c++ size()` will return 0.

??? note "Parameters"
    Not applicable

??? note "Return"
    Returns a `#!c++ std::pair<pointer, index_type>` containing a pointer to
    the array and the number of elements in the array.

??? note "Contracts"

    ??? summary "Expects"
        - None

    ??? summary "Ensures"
        - `#!c++ get()` == nullptr
        - `#!c++ size()` == 0
        - if ret.first == nullptr, ret.second == 0
        - if ret.first != nullptr, ret.second >= 1

!!! example "Usage"

    ``` c++
    auto a = bsl::make_dynarray<int>(1);
    auto p = a.release();
    delete[] p.first;
    ```

---

<h3 id="dynarray__reset">
reset
</h3>

``` c++
constexpr auto
reset(pointer ptr = {}, index_type count = {}) noexcept -> void

constexpr auto
reset(const std::pair<pointer, index_type> &info) noexcept -> void

```

Transfers ownership of an array at `#!c++ ptr` of size `#!c++ count` from the caller to the `#!c++ bsl::dynarray`. If the `#!c++ bsl::dynarray` already owns an array, the old array is deleted using the Deleter before ownership is transferred. A std::pair version of this function is also provided that is equivalent to `#!c++ reset(info.first, info.second)`.

??? note "Parameters"

    ??? summary "ptr"
        a pointer to the array (a continuous memory block) the
        `#!c++ bsl::dynarray` will manage. If the default deleter is used,
        this memory must be allocated using the `#!c++ new []` operator.

    ??? summary "count"
        the number of elements in the array.

        !!! warning "Note"
            the count does not refer to the number of bytes, but rather the                 total number of elements.

    ??? summary "info (optional)"
        a `#!c++ std::pair` containing a pointer to the array (a continuous
        memory block) the `#!c++ bsl::dynarray` will manage and the number of
        elements in the array. If the default deleter is used, this memory must
        be allocated using the `#!c++ new []` operator.

        !!! warning "Note"
            the count does not refer to the number of bytes, but rather the                 total number of elements.

??? note "Return"
    Not applicable

??? note "Contracts"

    ??? summary "Expects"
        - if ptr == nullptr, count == 0
        - if ptr != nullptr, count >= 1

    ??? summary "Ensures"
        - if ptr == nullptr, empty() == true
        - if ptr != nullptr, empty() == false

!!! example "Usage"

    ``` c++
    auto a = bsl::make_dynarray<int>(1);
    auto p = a.release();

    a.reset(p.first, p.second);
    a.reset(a.release);
    ```

---

<h3 id="dynarray__swap">
swap
</h3>

``` c++
constexpr auto
swap(dynarray &other) noexcept -> void
```

Swaps ownership of an array between other and this. Both arrays remain unaffected other than the ownership change.

??? note "Parameters"

    ??? summary "other"
        the `#!c++ bsl::dynarray` swap ownership with.

??? note "Return"
    Not applicable

??? note "Contracts"

    ??? summary "Expects"
        - None

    ??? summary "Ensures"
        - None

!!! example "Usage"

    ``` c++
    auto a1 = bsl::make_dynarray<int>(1);
    auto a2 = bsl::make_dynarray<int>(1);
    a1.swap(a2);
    ```

---

<h3 id="dynarray__get">
get
</h3>

``` c++
[[nodiscard]] constexpr auto
get() const -> pointer
```

Returns a pointer to the array managed by this `#!c++ bsl::dynarray`.

??? note "Parameters"
    Not applicable

??? note "Return"
    Returns a pointer to the array managed by this `#!c++ bsl::dynarray`.

??? note "Contracts"

    ??? summary "Expects"
        - None

    ??? summary "Ensures"
        - None

!!! example "Usage"

    ``` c++
    auto a = bsl::make_dynarray<int>(1);
    auto p = a.get();
    ```

---

<h3 id="dynarray__get_deleter">
get_deleter
</h3>

``` c++
[[nodiscard]] constexpr auto
get_deleter() noexcept -> deleter_type &

[[nodiscard]] constexpr auto
get_deleter() const noexcept -> const_deleter_type &
```

Returns an l-value reference to the Deleter that this `#!c++ bsl::dynarray` will use to delete the array that it manages. Since the `#!c++ bsl::dynarray` uses Empty Base Optimizations to reduce its overall size, it is likely that the returned reference is equivalent to `#!c++* this`.

??? note "Parameters"
    Not applicable

??? note "Return"
    Returns an l-value reference to the Deleter that this `#!c++ bsl::dynarray`
    will use to delete the array that it manages.

??? note "Contracts"

    ??? summary "Expects"
        - None

    ??? summary "Ensures"
        - None

!!! example "Usage"

    ``` c++
    auto a = bsl::make_dynarray<int>(1);
    auto p = a.release();
    auto d = a.get_deleter();
    d(p.first, p.second);
    ```

---

<h3 id="dynarray__operator_bool">
operator bool
</h3>

``` c++
explicit operator bool() const noexcept
```

Returns true when this `#!c++ bsl::dynarray` manages a valid array. While this is equivalent to `#!c++ get() != nullptr`, this function ensures that if it returns true, `#!c++ size() >= 1` and if it returns false, `#!c++ size() == 0`.

??? note "Parameters"
    Not applicable

??? note "Return"
    Returns true when this `#!c++ bsl::dynarray` manages a valid array.

??? note "Contracts"

    ??? summary "Expects"
        - None

    ??? summary "Ensures"
        - if `#!c++ get()` == nullptr, `#!c++ size()` == 0
        - if `#!c++ get()` != nullptr, `#!c++ size()` >= 1

!!! example "Usage"

    ``` c++
    auto a = bsl::make_dynarray<int>(1);
    if (a) {
        std::cout << "dynarray is valid\n";
    }
    else {
        std::cout << "dynarray is invalid\n";
    }
    ```

---

<h3 id="dynarray__operator_subscript">
operator[]
</h3>

``` c++
[[nodiscard]] constexpr auto
operator[](index_type i) -> reference

[[nodiscard]] constexpr auto
operator[](index_type i) const -> const_reference
```

Returns an l-value reference to the element at index_type i in the array managed by this `#!c++ bsl::dynarray`.

!!! warning
    This function will throw when both BSL_CORE_GUIDELINE_COMPLIANT
    and BSL_THROW_ON_CONTRACT_VIOLATION are defined prior to including
    the BSL when a contract violation occurs. Otherwise, this function will
    call `#!c++ std::terminate()` when both BSL_CORE_GUIDELINE_COMPLIANT
    and BSL_TERMINATE_ON_CONTRACT_VIOLATION are defined. If neither of        these cases are true, the execution of this function is undefined when a
    contract violation occurs (such as an out of range error).

??? note "Parameters"

    ??? summary "i"
        The index of the element within the array that this `#!c++
        bsl::dynarray` manages to return.

??? note "Return"
    Returns an l-value reference to the element at index_type i in the array
    managed by this `#!c++ bsl::dynarray`.

??? note "Contracts"

    ??? summary "Expects"
        - `#!c++ i` < `#!c++ size()`

    ??? summary "Ensures"
        - None

!!! example "Usage"

    ``` c++
    auto a = bsl::make_dynarray<int>(1);
    a[0] = 42;
    a[1] = 23; // <--- throws, calls std::terminate() or is undefined
    ```

---

<h3 id="dynarray__at">
at
</h3>

``` c++
[[nodiscard]] constexpr auto
at(index_type pos) -> reference

[[nodiscard]] constexpr auto
at(index_type pos) const -> const_reference
```

Returns an l-value reference to the element at index_type pos in the array managed by this `#!c++ bsl::dynarray`. This function will always throw a `#!c++ std::out_of_range` exception when the index_type pos is >= `#!c++ size()`.

??? note "Parameters"

    ??? summary "i"
        The index of the element within the array that this `#!c++
        bsl::dynarray` manages to return.

??? note "Return"
    Returns an l-value reference to the element at index_type i in the array
    managed by this `#!c++ bsl::dynarray`.

??? note "Contracts"

    ??? summary "Expects"
        - `#!c++ i` < `#!c++ size()`

    ??? summary "Ensures"
        - None

!!! example "Usage"

    ``` c++
    auto a = bsl::make_dynarray<int>(1);
    a.at(0) = 42;
    a.at(1) = 23; // <--- throws
    ```

---

<h3 id="dynarray__front">
front
</h3>

``` c++
[[nodiscard]] constexpr auto
front() -> reference

[[nodiscard]] constexpr auto
front() const -> const_reference
```

Returns an l-value reference to the element at the beginning of the array managed by this `#!c++ bsl::dynarray`. This is equivalent to `#!c++ [0]`.

!!! warning
    This function will throw when both BSL_CORE_GUIDELINE_COMPLIANT
    and BSL_THROW_ON_CONTRACT_VIOLATION are defined prior to including
    the BSL when a contract violation occurs. Otherwise, this function will
    call `#!c++ std::terminate()` when both BSL_CORE_GUIDELINE_COMPLIANT
    and BSL_TERMINATE_ON_CONTRACT_VIOLATION are defined. If neither of        these cases are true, the execution of this function is undefined when a
    contract violation occurs (such as an out of range error).

??? note "Parameters"
    Not applicable

??? note "Return"
    Returns an l-value reference to the element at the beginning of the array
    managed by this `#!c++ bsl::dynarray`.

??? note "Contracts"

    ??? summary "Expects"
        - `#!c++ !empty()`

    ??? summary "Ensures"
        - None

!!! example "Usage"

    ``` c++
    auto a1 = bsl::make_dynarray<int>(1);
    a1.front() = 42;

    auto a2 = bsl::dynarray<int>();
    a2.front() = 42; // <--- throws, calls std::terminate() or is undefined
    ```

---

<h3 id="dynarray__back">
back
</h3>

``` c++
[[nodiscard]] constexpr auto
back() -> reference

[[nodiscard]] constexpr auto
back() const -> const_reference
```

Returns an l-value reference to the element at the end of the array managed by this `#!c++ bsl::dynarray`. This is equivalent to `#!c++ [size() - 1]`.

!!! warning
    This function will throw when both BSL_CORE_GUIDELINE_COMPLIANT
    and BSL_THROW_ON_CONTRACT_VIOLATION are defined prior to including
    the BSL when a contract violation occurs. Otherwise, this function will
    call `#!c++ std::terminate()` when both BSL_CORE_GUIDELINE_COMPLIANT
    and BSL_TERMINATE_ON_CONTRACT_VIOLATION are defined. If neither of        these cases are true, the execution of this function is undefined when a
    contract violation occurs (such as an out of range error).

??? note "Parameters"
    Not applicable

??? note "Return"
    Returns an l-value reference to the element at the end of the array managed
    by this `#!c++ bsl::dynarray`.

??? note "Contracts"

    ??? summary "Expects"
        - `#!c++ !empty()`

    ??? summary "Ensures"
        - None

!!! example "Usage"

    ``` c++
    auto a1 = bsl::make_dynarray<int>(1);
    a1.back() = 42;

    auto a2 = bsl::dynarray<int>();
    a2.back() = 42; // <--- throws, calls std::terminate() or is undefined
    ```

---

<h3 id="dynarray__data">
data
</h3>

``` c++
[[nodiscard]] constexpr auto
data() noexcept -> pointer

[[nodiscard]] constexpr auto
data() const noexcept -> const_pointer
```

Returns a pointer to the array managed by this `#!c++ bsl::dynarray`.

??? note "Parameters"
    Not applicable

??? note "Return"
    Returns a pointer to the array managed by this `#!c++ bsl::dynarray`.

??? note "Contracts"

    ??? summary "Expects"
        - None

    ??? summary "Ensures"
        - None

!!! example "Usage"

    ``` c++
    auto a = bsl::make_dynarray<int>(1);
    auto p = a.data();
    ```

---

<h3 id="dynarray__begin_cbegin">
begin / cbegin
</h3>

``` c++
[[nodiscard]] constexpr auto
begin() noexcept -> iterator

[[nodiscard]] constexpr auto
begin() const noexcept -> const_iterator

[[nodiscard]] constexpr auto
cbegin() const noexcept -> const_iterator
```

Returns an iterator to the first element in the array managed by this `#!c++ bsl::dynarray`.

!!! warning
    Iterators will throw when both BSL_CORE_GUIDELINE_COMPLIANT
    and BSL_THROW_ON_CONTRACT_VIOLATION are defined prior to including
    the BSL when a contract violation occurs. Otherwise, iterators will
    call `#!c++ std::terminate()` when both BSL_CORE_GUIDELINE_COMPLIANT
    and BSL_TERMINATE_ON_CONTRACT_VIOLATION are defined. If neither of        these cases are true, dereferencing an iterator is undefined when a
    contract violation occurs (such as an out of range error). It should be
    noted that unlike a `#!c++ gsl::span`, iterators only check for contract
    violations when dereferencing. Arithmetic on an iterator (including moving
    an iterator well beyond the bounds of the array) has no affect until the
    iterator is finally dereferenced.

??? note "Parameters"
    Not applicable

??? note "Return"
    Returns an iterator to the first element in the array managed by this
    `#!c++ bsl::dynarray`.

??? note "Contracts"

    ??? summary "Expects"
        - None

    ??? summary "Ensures"
        - None

!!! example "Usage"

    ``` c++
    auto a = bsl::make_dynarray<int>(42);

    for (auto iter = a.begin(); iter != a.end(); iter++) {
        *iter = 42;
    }

    for (const auto &elem : a) {
        std::cout << elem << '\n';
    }
    ```

---

<h3 id="dynarray__end_cend">
end / cend
</h3>

``` c++
[[nodiscard]] constexpr auto
end() noexcept -> iterator

[[nodiscard]] constexpr auto
end() const noexcept -> const_iterator

[[nodiscard]] constexpr auto
cend() const noexcept -> const_iterator
```

Returns an iterator to the element after the last element in the array managed by this `#!c++ bsl::dynarray`.

!!! warning
    Iterators will throw when both BSL_CORE_GUIDELINE_COMPLIANT
    and BSL_THROW_ON_CONTRACT_VIOLATION are defined prior to including
    the BSL when a contract violation occurs. Otherwise, iterators will
    call `#!c++ std::terminate()` when both BSL_CORE_GUIDELINE_COMPLIANT
    and BSL_TERMINATE_ON_CONTRACT_VIOLATION are defined. If neither of        these cases are true, dereferencing an iterator is undefined when a
    contract violation occurs (such as an out of range error). It should be
    noted that unlike a `#!c++ gsl::span`, iterators only check for contract
    violations when dereferencing. Arithmetic on an iterator (including moving
    an iterator well beyond the bounds of the array) has no affect until the
    iterator is finally dereferenced.

??? note "Parameters"
    Not applicable

??? note "Return"
    Returns an iterator to the element after the last element in the array
    managed by this `#!c++ bsl::dynarray`.

??? note "Contracts"

    ??? summary "Expects"
        - None

    ??? summary "Ensures"
        - None

!!! example "Usage"

    ``` c++
    auto a = bsl::make_dynarray<int>(42);

    for (auto iter = a.begin(); iter != a.end(); iter++) {
        *iter = 42;
    }

    for (const auto &elem : a) {
        std::cout << elem << '\n';
    }
    ```

---

<h3 id="dynarray__rbegin_crbegin">
rbegin / crbegin
</h3>

``` c++
[[nodiscard]] constexpr auto
rbegin() noexcept -> reverse_iterator

[[nodiscard]] constexpr auto
rbegin() const noexcept -> const_reverse_iterator

[[nodiscard]] constexpr auto
crbegin() const noexcept -> const_reverse_iterator
```

Returns a reverse iterator to the last element in the array managed by this `#!c++ bsl::dynarray`.

!!! warning
    Iterators will throw when both BSL_CORE_GUIDELINE_COMPLIANT
    and BSL_THROW_ON_CONTRACT_VIOLATION are defined prior to including
    the BSL when a contract violation occurs. Otherwise, iterators will
    call `#!c++ std::terminate()` when both BSL_CORE_GUIDELINE_COMPLIANT
    and BSL_TERMINATE_ON_CONTRACT_VIOLATION are defined. If neither of        these cases are true, dereferencing an iterator is undefined when a
    contract violation occurs (such as an out of range error). It should be
    noted that unlike a `#!c++ gsl::span`, iterators only check for contract
    violations when dereferencing. Arithmetic on an iterator (including moving
    an iterator well beyond the bounds of the array) has no affect until the
    iterator is finally dereferenced.

??? note "Parameters"
    Not applicable

??? note "Return"
    Returns a reverse iterator to the last element in the array managed by this
    `#!c++ bsl::dynarray`.

??? note "Contracts"

    ??? summary "Expects"
        - None

    ??? summary "Ensures"
        - None

!!! example "Usage"

    ``` c++
    auto a = bsl::make_dynarray<int>(42);

    for (auto iter = a.rbegin(); iter != a.rend(); iter++) {
        *iter = 42;
    }
    ```

---

<h3 id="dynarray__rend_crend">
rend / crend
</h3>

``` c++
[[nodiscard]] constexpr auto
rend() noexcept -> reverse_iterator

[[nodiscard]] constexpr auto
rend() const noexcept -> const_reverse_iterator

[[nodiscard]] constexpr auto
crend() const noexcept -> const_reverse_iterator
```

Returns a reverse iterator to the element before the first element in the array managed by this `#!c++ bsl::dynarray`.

!!! warning
    Iterators will throw when both BSL_CORE_GUIDELINE_COMPLIANT
    and BSL_THROW_ON_CONTRACT_VIOLATION are defined prior to including
    the BSL when a contract violation occurs. Otherwise, iterators will
    call `#!c++ std::terminate()` when both BSL_CORE_GUIDELINE_COMPLIANT
    and BSL_TERMINATE_ON_CONTRACT_VIOLATION are defined. If neither of        these cases are true, dereferencing an iterator is undefined when a
    contract violation occurs (such as an out of range error). It should be
    noted that unlike a `#!c++ gsl::span`, iterators only check for contract
    violations when dereferencing. Arithmetic on an iterator (including moving
    an iterator well beyond the bounds of the array) has no affect until the
    iterator is finally dereferenced.

??? note "Parameters"
    Not applicable

??? note "Return"
    Returns a reverse iterator to the element before the first element in the
    array managed by this `#!c++ bsl::dynarray`.

??? note "Contracts"

    ??? summary "Expects"
        - None

    ??? summary "Ensures"
        - None

!!! example "Usage"

    ``` c++
    auto a = bsl::make_dynarray<int>(42);

    for (auto iter = a.rbegin(); iter != a.rend(); iter++) {
        *iter = 42;
    }
    ```

---

<h3 id="dynarray__empty">
empty
</h3>

``` c++
[[nodiscard]] constexpr auto
empty() const noexcept -> bool
```

Returns true when this `#!c++ bsl::dynarray` is empty. While this is equivalent to `#!c++ size() == 0`, this function ensures that if it returns true, `#!c++ get() == nullptr` and if it returns false, `#!c++ get() != nullptr`.

??? note "Parameters"
    Not applicable

??? note "Return"
    Returns true when this `#!c++ bsl::dynarray` is empty.

??? note "Contracts"

    ??? summary "Expects"
        - None

    ??? summary "Ensures"
        - if `#!c++ get()` == nullptr, `#!c++ size()` == 0
        - if `#!c++ get()` != nullptr, `#!c++ size()` >= 1

!!! example "Usage"

    ``` c++
    auto a = bsl::make_dynarray<int>(1);

    if (a.empty()) {
        std::cout << "dynarray is empty\n";
    }
    else {
        std::cout << "dynarray is not empty\n";
    }
    ```

---

<h3 id="dynarray__size_ssize">
size / ssize
</h3>

``` c++
[[nodiscard]] constexpr auto
size() const noexcept -> index_type

[[nodiscard]] constexpr auto
ssize() const noexcept -> difference_type
```

Returns the number of elements in this `#!c++ bsl::dynarray`.

??? note "Parameters"
    Not applicable

??? note "Return"
    Returns the number of elements in this `#!c++ bsl::dynarray`.

??? note "Contracts"

    ??? summary "Expects"
        - None

    ??? summary "Ensures"
        - None

!!! example "Usage"

    ``` c++
    auto a = bsl::make_dynarray<int>(1);
    std::cout << a.size() << '\n';
    ```

---

<h3 id="dynarray__size_bytes">
size_bytes
</h3>

``` c++
[[nodiscard]] constexpr auto
size_bytes() const noexcept -> index_type
```

Returns the size of this `#!c++ bsl::dynarray` in bytes, not elements. This is equivalent to `#!c++ size() * sizeof T`.

??? note "Parameters"
    Not applicable

??? note "Return"
    Returns the size of this `#!c++ bsl::dynarray` in bytes, not elements.

??? note "Contracts"

    ??? summary "Expects"
        - None

    ??? summary "Ensures"
        - None

!!! example "Usage"

    ``` c++
    auto a = bsl::make_dynarray<int>(1);
    std::cout << a.size_bytes() << '\n';
    ```

---

<h3 id="dynarray__max_size">
max_size
</h3>

``` c++
[[nodiscard]] constexpr auto
max_size() const noexcept -> index_type
```

Returns the max number of elements this `#!c++ bsl::dynarray` can store. This is equivalent to `#!c++ std::numeric_limits<difference_type>::max() / sizeof T;`

??? note "Parameters"
    Not applicable

??? note "Return"
    Returns the max number of elements this `#!c++ bsl::dynarray` can store.

??? note "Contracts"

    ??? summary "Expects"
        - None

    ??? summary "Ensures"
        - None

!!! example "Usage"

    ``` c++
    auto a = bsl::make_dynarray<int>(1);
    std::cout << a.max_size() << '\n';
    ```

---

<h3 id="dynarray__fill">
fill
</h3>

``` c++
constexpr auto
fill(const T &value) -> void
```

Value-initializes each element in the `#!c++ bsl::dynarray` by copying value.

??? todo

    - [ ] Add some additional fill() functions (an operator=() versions) to
          make it easier to work with the array.

??? note "Parameters"

    ??? summary "value"
        the value to copy into each element in the `#!c++ bsl::dynarray`.

??? note "Return"
    Not applicable

??? note "Contracts"

    ??? summary "Expects"
        - None

    ??? summary "Ensures"
        - None

!!! example "Usage"

    ``` c++
    auto a = bsl::make_dynarray<int>(1);
    a.fill(42);
    ```

---

<h3 id="dynarray__make_dynarray">
make_dynarray
</h3>

``` c++
template<typename T> constexpr auto
make_dynarray(size_t count) -> dynarray<T>
```

Creates a `#!c++ bsl::dynarray` of size count using the `#!c++ new []` operator and the default deleter. In addition, each element in the `#!c++ bsl::dynarray` is value-initialized using `#!c++ T()`.

!!! tip
    Whenever possible `#!c++ bsl::make_dynarray` should be used instead of
    manually creating a `#!c++ bsl::dynarray` as this function ensures that
    the size of the array matches the memory allocated.

??? note "Parameters"

    ??? summary "count"
        The total number of elements in the array to create.

??? note "Return"
    A `#!c++ bsl::dynarray` of size count.

??? note "Contracts"

    ??? summary "Expects"
        - `#!c++ count` > 0

    ??? summary "Ensures"
        - None

!!! example "Usage"

    ``` c++
    auto a = bsl::make_dynarray<int>(42);
    ```

---

<h3 id="dynarray__make_dynarray_default_init">
make_dynarray_default_init
</h3>

``` c++
template<typename T> constexpr auto
make_dynarray_default_init(size_t count) -> dynarray<T>
```

Creates a `#!c++ bsl::dynarray` of size count using the `#!c++ new []` operator and the default deleter. In addition, each element in the `#!c++ bsl::dynarray` is default-initialized.

!!! tip
    Whenever possible `#!c++ bsl::make_dynarray_default_init` should be used
    instead of manually creating a `#!c++ bsl::dynarray` as this function
    ensures that the size of the array matches the memory allocated.

??? note "Parameters"

    ??? summary "count"
        The total number of elements in the array to create.

??? note "Return"
    A `#!c++ bsl::dynarray` of size count.

??? note "Contracts"

    ??? summary "Expects"
        - `#!c++ count` > 0

    ??? summary "Ensures"
        - None

!!! example "Usage"

    ``` c++
    auto a = bsl::make_dynarray<int>(42);
    ```

---

<h3 id="dynarray__operator_comparison_equals">
operator== / operator!=
</h3>

``` c++
template<typename T1, typename D1, typename T2, typename D2>
constexpr bool
operator==(const bsl::dynarray<T1, D1> &lhs, const bsl::dynarray<T2, D2> &rhs)

template<typename T1, typename D1, typename T2, typename D2>
constexpr bool
operator!=(const bsl::dynarray<T1, D1> &lhs, const bsl::dynarray<T2, D2> &rhs)
```

Returns true if the lhs `#!c++ bsl::dynarray` and the rhs `#!c++ bsl::dynarray` are equal (and vice versa). A `#!c++ bsl::dynarray` is equal to another `#!c++ bsl::dynarray` if they are the same size, and each element in each `#!c++ bsl::dynarray` compares equal at the same position.

??? todo

    - [ ] Add support for the >, <, >= and <= operators

??? note "Parameters"

    ??? summary "lhs"
        A `#!c++ bsl::dynarray` to compare

    ??? summary "rhs"
        A `#!c++ bsl::dynarray` to compare

??? note "Return"
    Returns true if the lhs `#!c++ bsl::dynarray` and the rhs
    `#!c++ bsl::dynarray` are equal (and vice versa).

??? note "Contracts"

    ??? summary "Expects"
        - None

    ??? summary "Ensures"
        - None

!!! example "Usage"

    ``` c++
    auto a1 = bsl::make_dynarray<int>(1);
    auto a2 = bsl::make_dynarray<int>(42);

    if (a1 == a2) {
        std::cout << "lhs and rhs are equal\n";
    }
    else {
        std::cout << "lhs and rhs are not equal\n";
    }
    ```

---

<h3 id="dynarray__operator_ostream">
operator<<
</h3>

``` c++
template<typename CharT, typename Traits, typename T, typename D>
std::basic_ostream<CharT, Traits> &
operator<<(std::basic_ostream<CharT, Traits> &os, const bsl::dynarray<T, D> &da)
```

Adds the `#!c++ bsl::dynarray` to the output stream. This is equivalent to `#!c++ os << static_cast<void *>(da.get())`.

??? note "Parameters"

    ??? summary "os"
        The output stream to add the `#!c++ bsl::dynarray` to.

    ??? summary "rhs"
        The `#!c++ bsl::dynarray` to add to the output stream

??? note "Return"
    Returns an l-value reference to the output stream.

??? note "Contracts"

    ??? summary "Expects"
        - None

    ??? summary "Ensures"
        - None

!!! example "Usage"

    ``` c++
    auto a = bsl::make_dynarray<int>(1);
    std::cout << a << '\n';
    ```
