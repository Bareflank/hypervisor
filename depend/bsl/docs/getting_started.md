# **Getting Started**

The Bareflank Support Library is a header only library, and as such, usage of this library is as simple as downloading and including the `#!c++ bsl.h` header. Alternatively, this library support the use of `#!cmake find_package()` and traditional installs.

## **Installation**

To install the BSL onto your local system, run the following from a bash terminal to download the latest source code from GitHub:

``` bash
git clone https://github.com/bareflank/bsl
cd bsl
```

Once you have the latest source code, the following can be run to perform an install:

``` bash
cmake .
sudo make install
```

Alternatively, you can install the BSL into a custom prefix as follows:

``` bash
cmake . -DCMAKE_INSTALL_PREFIX=<prefix path>
sudo make install
```

## **Usage**

The easiest way to use the BSL is to simply include it as follows:

``` c++
#include "path/bsl.h"
```

If the BSL is installed onto your local system or a custom prefix, you can use the BSL as the following:

``` c++
#include <bsl/bsl.h>
```


Finally, once compiled, you can use `#!cmake find_package()` with CMake as follows:

``` cmake
cmake_minimum_required(VERSION 3.13)
project(dynarray CXX)

find_package(bsl)
set(CMAKE_CXX_STANDARD 17)

add_executable(a.out main.cpp)
target_link_libraries(a.out PRIVATE bsl)
```

And then include the BSL as follows:

``` c++
#include <bsl.h>
```

## **Compilation Options**

The BSL comes with both a set of examples as well as unit tests. By default, these are both built when running `#!bash make`. If you wish, you can turn these off as follows:

``` bash
cmake . -DBUILD_EXAMPLES=OFF -DBUILD_TESTS=OFF
```

The tests and examples can be built using Clang Tidy and Cppcheck to ensure the BSL is statically analyzed during development. To enable this, use the following:

``` bash
cmake . -DENABLE_CLANG_TIDY=ON -DENABLE_CPPCHECK=ON
```

Dynamic analysis using Google's sanitizers can be enabled as follows:

``` bash
cmake . -DCMAKE_BUILD_TYPE=ASAN
```

or

``` bash
cmake . -DCMAKE_BUILD_TYPE=UBSAN
```

Finally, to turn all of these features (minus ASAN), simply run cmake with the following to enable development mode, which should be used prior to submitting
a pull request.

``` bash
cmake . -DENABLE_DEVELOPMENT=ON
```

## **Build Targets**

In addition to the typical build targets that CMake already provides, the BSL also provides targets to format the source code as well as execute the provided unit tests if `#!cmake BUILD_TESTS=ON`.

To format the source code, Clang Format 8 or higher must be installed to execute the following

``` bash
make format
```

To run the unit tests, execute the following:

``` bash
make unittests
```
