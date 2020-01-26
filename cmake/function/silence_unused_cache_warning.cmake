function(silence_unused_cache_warning)
    get_cmake_property(_vars CACHE_VARIABLES)
    foreach (_var ${_vars})
        set(${_var} ${${_var}})
    endforeach()
endfunction(silence_unused_cache_warning)
