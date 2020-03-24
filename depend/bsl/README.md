# **Bareflank Support Library**

## **Description**

The Bareflank Support Library (BSL) is a header-only library that provides an AUTOSAR and C++ Core Guideline compliant implementation of the C++ Standard Library. To achieve this, the BSL does not adhere to the C++ Standard Library specification, but attempts to where possible (as the C++ Standard Library specification in its current form is not compliant with either set of guidelines). Since a number of critical systems applications do not support dynamic memory or C++ exceptions, the BSL uses neither, but is capable of coexisting with the C++ Standard Library including properly handling if exceptions are enabled and used.

[![Material for MkDocs](https://github.com/Bareflank/bsl/raw/master/docs/images/example.png)](https://github.com/Bareflank/bsl/raw/master/docs/images/example.png)

## **Quick start**

![GitHub release (latest by date)](https://img.shields.io/github/v/release/bareflank/bsl?color=brightgreen)

Get the latest version of the BSL from GitHub:

``` bash
git clone https://github.com/rianquinn/bsl
mkdir bsl/build && cd bsl/build
cmake ..
make install -j
```

Enjoy:

``` c++
#include <bsl/discard.hpp>
#include <bsl/main.hpp>
#include <bsl/array.hpp>

namespace bsl
{
    bsl::exit_code
    entry(bsl::arguments const &args) noexcept
    {
        bsl::discard(args);
        bsl::array<bsl::int32, 42> arr{};

        bsl::foreach(arr, [](auto &elem, auto index){
            elem = index;
        });

        bsl::foreach(arr, [](auto const &elem, auto){
            bsl::print("{} ", elem);
        });

        bsl::print("\n");
        return bsl::exit_code::exit_success;
    }
}

```

## **Build Requirements**
Currently, the BSL only supports the Clang/LLVM 9+ compiler. This, however, ensures the BSL can be natively compiled on Windows including support for cross-compiling.

### **Windows**
To compile the BSL on Windows, you must first install the following:
- [Visual Studio](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=Community&rel=16) (Enable "Desktop development with C++")
- [LLVM 9+](https://github.com/llvm/llvm-project/releases)
- [CMake 3.16+](https://cmake.org/download/)

Visual Studio is needed as it contains Windows specific libraries that are needed during compilation. Instead of using the Clang/LLVM project that natively ships with Visual Studio, we use the standard Clang/LLVM binaries provided by the LLVM project which ensures we get all of the tools including LLD, Clang Tidy and Clang Format. CMake 3.16+ is needed as we currently make use of some features in CMake 3.16. If you do not want to use the Visual Studio Command Prompt, you will need to add "Ninja" to your path. Either search for Ninja on your system, or download it from here (just copy Ninja to LLVM's bin directory):
- [Ninja](https://github.com/ninja-build/ninja/releases)

Once you have everything installed, you can build the BSL using the following:

``` bash
git clone https://github.com/rianquinn/bsl
mkdir bsl/build && cd bsl/build
cmake -G Ninja -DCMAKE_CXX_COMPILER="clang++" ..
ninja
```

As well as install the BSL using:
```
ninja install
```

### **Ubuntu Linux**
TBD

### **Arch Linux**
TBD

### **macOS**
TBD

## **Resources**

[![Board Status](https://dev.azure.com/bareflank/0e2ee159-02d3-456c-908e-b6684055bb6c/183e6af6-db8f-4e28-910e-33ffd32d94a9/_apis/work/boardbadge/2e44e3c9-beea-457e-9786-4af440d91aa8)](https://dev.azure.com/bareflank/0e2ee159-02d3-456c-908e-b6684055bb6c/_boards/board/t/183e6af6-db8f-4e28-910e-33ffd32d94a9/Microsoft.RequirementCategory/)
[![Join the chat](https://img.shields.io/badge/chat-on%20Slack-brightgreen.svg)](https://app.slack.com/client/TPN7LQKRP/CPJLF1RV1)

The Bareflank Support Library provides a ton of useful resources to learn how to use the library including:

-   **Documentation**: <https://bareflank.github.io/bsl/>
-   **Examples**: <https://github.com/Bareflank/bsl/tree/master/examples>
-   **Unit Tests**: <https://github.com/Bareflank/bsl/tree/master/tests>

If you have any questions, bugs, or feature requests, please feel free to ask on any of the following:

-   **Issue Tracker**: <https://github.com/Bareflank/bsl/issues>
-   **Slack**: <https://app.slack.com/client/TPN7LQKRP/CPJLF1RV1>

And as always, we are always looking for more help:

-   **Pull Requests**: <https://github.com/Bareflank/bsl/pulls>
-   **Contributing Guidelines**: <https://github.com/Bareflank/bsl/blob/master/contributing.md>

## **Testing**
[![Build Status](https://dev.azure.com/bareflank/bsl/_apis/build/status/Bareflank.bsl?branchName=master)](https://dev.azure.com/bareflank/bsl/_build/latest?definitionId=2&branchName=master)
[![codecov](https://codecov.io/gh/Bareflank/bsl/branch/master/graph/badge.svg)](https://codecov.io/gh/Bareflank/bsl)
[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/Bareflank/bsl.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/Bareflank/bsl/context:cpp)
![Codacy grade](https://img.shields.io/codacy/grade/9e55fc17a08d4e2abe51d82f09f4449f)
[![CodeFactor](https://www.codefactor.io/repository/github/bareflank/bsl/badge)](https://www.codefactor.io/repository/github/bareflank/bsl)

The Bareflank Support Library leverages the following tools to ensure the highest possible code quality. Each pull request undergoes the following rigorous testing and review:

-   **Static Analysis:** Clang Tidy, SonarCloud, Perforce Helix QAC
-   **Dynamic Analysis:** Google's ASAN and UBSAN
-   **Code Coverage:** LLVM Code Coverage with CodeCov
-   **Coding Standards**: [AUTOSAR C++14](https://www.autosar.org/fileadmin/user_upload/standards/adaptive/17-03/AUTOSAR_RS_CPP14Guidelines.pdf)
-   **Style**: Clang Format and Git Check
-   **Documentation**: Doxygen
