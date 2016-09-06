# Libc++

Bareflank leverages [libc++](http://libcxx.llvm.org) to provide support for the C++ STL. In addition, Bareflank leverages Microsoft's Guideline Support Library ([GSL](https://github.com/Microsoft/GSL)) to provide support for the [C++ Core Guidelines](https://github.com/isocpp/CppCoreGuidelines). Although the C++ STL is supported, not all of the the STL is supported. For example, `fstream` makes no sense in the VMM and will likely never be supported. The following provides a list of supported features in the STL that are known to work, and have been unit tested:

## [Containers](http://www.cplusplus.com/reference/stl/)
\<complete once unit tests are done\>

## [Input/Output](http://www.cplusplus.com/reference/iolibrary/)
\<complete once unit tests are done\>

## [Multi-threading](http://www.cplusplus.com/reference/multithreading/)
\<complete once unit tests are done\>

## [Other](http://www.cplusplus.com/reference/std/)
\<complete once unit tests are done\>
