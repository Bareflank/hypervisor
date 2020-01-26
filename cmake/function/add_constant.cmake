function(add_constant)
    set(oneVal CONST_NAME CONST_VALUE DESCRIPTION)
    cmake_parse_arguments(ARG "" "${oneVal}" "" ${ARGN})

    if(NOT DEFINED ARG_CONST_NAME)
        message(FATAL_ERROR "Constants must provide a CONST_NAME")
    endif()

    if(NOT DEFINED ARG_CONST_VALUE)
        message(FATAL_ERROR "Constants must provide a CONST_VALUE")
    endif()

    if(NOT DEFINED ${ARG_CONST_NAME})
        set(${ARG_CONST_NAME} ${ARG_CONST_VALUE} CACHE INTERNAL ${ARG_DESCRIPTION})
    else()
        set(${ARG_CONST_NAME} ${${ARG_CONST_NAME}} CACHE INTERNAL ${ARG_DESCRIPTION})
    endif()

    mark_as_advanced(${ARG_CONST_NAME})
endfunction(add_constant)
