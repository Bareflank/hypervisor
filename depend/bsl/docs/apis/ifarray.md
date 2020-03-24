## **Input File Array**

C++ currently doesn't have a fast, simple method for reading in the entire contents of a file into an array. The best options are:

- `#!c++ std::vector`
- `#!c++ std::unique_ptr`

In either case, likely the fastest method is to use `#!c++ std::fstream` to open a file and then load the `#!c++ std::vector` or `#!c++ std::unique_ptr` with the contents of the file using the read function. The problem with `#!c++ std::vector` is that you would have to create a value-initialized array of memory based on the size of the file, and then load that array with the file's contents. For large files this is problematic as this requires the use of value-initialization even though you are about to initialize the contents of the vector with the file's contents. You could use a `#!c++ std::unique_ptr` to overcome this problem, but the `#!c++ std::unique_ptr` doesn't store the file's size. The other issue is with the `#!c++ read()` function that `#!c++ std::fstream` provides as this is not as fast as directly mapping the file using the operating system's mapping facilities. For large files, these mapping facilities make a big difference in performance.

The `#!c++ bsl:ifarray` attempts to solve these issues by:

- Using a `#!c++ bsl::dynarray` as the array type.
- Instead of using `#!c++ std::fstream`, the `#!c++ bsl::ifarray` uses the operating system's mapping functions to map in the file (read-only), providing the `#!c++ bsl::dynarray` with a pointer to the newly mapped file and a custom deleter that unmaps instead of deletes.
- Exposing all of the functionality of the `#!c++ bsl::dynarray`, providing a safe mechanism for working with the file.

In Bareflank, we need a class like this as we work with really large files (e.g., virtual machine images which can be gigabytes in size), but in general, this type of class should be helpful for anyone that needs array style access to a file.

!!! important

    The `#!c++ bsl::ifarray` inherits the `#!c++ bsl::dynarray`, providing
    access to all of the facilities that the `#!c++ bsl::dynarray` provides.
    This documentation only documents the functions unique to the
    `#!c++ bsl::ifarray` (e.g., the constructors). For more information about
    the APIs that the `#!c++ bsl::dynarray` provides in addition, please see
    the [Dynamic Array](#dynamic-array) APIs.

??? todo

    - [ ] Add support `#!c++ bsl::farray` for read/write access
    - [ ] Add support for `#!c++ bsl::ofarray` for write-only access

??? note "Template Parameters"

    ??? summary "T"
        The element type used to access the file. This defaults to uint8_t.

??? note "Member Types"

    !!! summary "value_type = T"
    !!! summary "element_type = T"
    !!! summary "index_type = std::size_t"
    !!! summary "difference_type = std::ptrdiff_t"
    !!! summary "reference = T &"
    !!! summary "const_reference = const T &"
    !!! summary "pointer = T *"
    !!! summary "const_pointer = const T *"
    !!! summary "deleter_type = bsl::farray_deleter<T>"
    !!! summary "const_deleter_type = const bsl::farray_deleter<T>"
    !!! summary "iterator = random_access_iterator"
    !!! summary "const_iterator = random_access_iterator"
    !!! summary "reverse_iterator = std::reverse_iterator"
    !!! summary "const_reverse_iterator = std::reverse_iterator"

### **Member Functions**

- [default constructor](#ifarray__default_constructor)
- [explicit constructors](#ifarray__explicit_constructors)

---

<h3 id="ifarray__default_constructor">
default constructor
</h3>

``` c++
constexpr ifarray() noexcept;
```

Creates a default initialized `#!c++ bsl::ifarray`. When called, `#!c++ get()` will return a null pointer, and `#!c++ size()` will return 0.

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
    auto a = bsl::ifarray<>();
    ```

<a name="ifarray2"></a>

---

<h3 id="ifarray__explicit_constructors">
explicit constructors
</h3>

``` c++
constexpr ifarray(const std::string &filename) noexcept;
```

Creates a `#!c++ bsl::ifarray` by opening the file using filename, and mapping the file using the operating system's mapping functions. This function will throw if the file cannot be opened or mapped.

!!! important
    The file is opened as read-only.

??? note "Parameters"
    Not applicable

??? note "Return"
    Not applicable

??? note "Contracts"

    ??? summary "Expects"
        - None

    ??? summary "Ensures"
        - None

!!! example "Usage"

    ``` c++
    auto a = bsl::ifarray<>("test.txt");

    for (const auto &c : a) {
        std::cout << c;
    }
    std::cout << '\n';
    ```
