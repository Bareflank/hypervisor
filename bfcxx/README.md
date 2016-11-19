# Libc++

Bareflank leverages [libc++](http://libcxx.llvm.org) to provide support for the C++ STL. In addition, Bareflank leverages Microsoft's Guideline Support Library ([GSL](https://github.com/Microsoft/GSL)) to provide support for the [C++ Core Guidelines](https://github.com/isocpp/CppCoreGuidelines). Although the C++ STL is supported, not all of the STL is supported. For example, `fstream` makes no sense in the VMM and will likely never be supported. The following provides a list of supported features in the STL that are known to work, and have been unit tested. If a C++ feature is not listed, it might still work, but simply has not been formally tested. Feel free use untested C++ features, but be warned that some might fail, and in unexpected ways.

## [Containers](http://www.cplusplus.com/reference/stl/)
- [std::array](http://www.cplusplus.com/reference/array/array/)
- [std::vector](http://www.cplusplus.com/reference/vector/vector/)
- [std::deque](http://www.cplusplus.com/reference/deque/deque/)
- [std::forward_list](http://www.cplusplus.com/reference/forward_list/forward_list/)
- [std::list](http://www.cplusplus.com/reference/list/list/)
- [std::stack](http://www.cplusplus.com/reference/stack/stack/)
- [std::queue](http://www.cplusplus.com/reference/queue/queue/)
- [std::priority_queue](http://www.cplusplus.com/reference/queue/priority_queue/)
- [std::set](http://www.cplusplus.com/reference/set/set/)
- [std::map](http://www.cplusplus.com/reference/map/map/)

## [Input/Output](http://www.cplusplus.com/reference/iolibrary/)
- [std::cout](http://www.cplusplus.com/reference/iostream/cout/)

## [Multi-threading](http://www.cplusplus.com/reference/multithreading/)
\<complete once unit tests are done\>

## [Other](http://www.cplusplus.com/reference/std/)
\<complete once unit tests are done\>
