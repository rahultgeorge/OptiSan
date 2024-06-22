cmake_minimum_required(VERSION 3.4.3)
project(BaggyBounds)

find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LT_LLVM_INSTALL_DIR}")

include_directories(${LLVM_INCLUDE_DIRS})
link_directories(${LLVM_LIBRARY_DIRS})
add_definitions(${LLVM_DEFINITIONS})

# Use the same C++ standard as LLVM does
set(CMAKE_CXX_STANDARD 14 CACHE STRING "")

# LLVM is normally built without RTTI. Be consistent with that.
if (NOT LLVM_ENABLE_RTTI)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
endif ()

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall\
    -fdiagnostics-color=always -Wno-everything ")

add_library(BaggyBounds MODULE
        pass/BaggyBoundsPass.cpp
        pass/BaggyBoundsPass.hh
        pass/BaggyBoundsSaveLocalsFunctionPass.cpp
        pass/BaggyBoundsPointersFunctionPass.cpp
        pass/address_constants.h
        pass/Util.cpp
        pass/Util.h
        )


add_library(baggy_rt_lib STATIC lib/address_constants.h
        lib/allocator.c
        lib/baggy_init.c
        lib/baggy_libc.c
        lib/baggy_slowpath.c
        lib/address_constants.h
        lib/util.c
        )

set_target_properties(baggy_rt_lib PROPERTIES
        COMPILE_FLAGS "-std=gnu99 -g -O2 -fPIC"
        )
set_target_properties(baggy_rt_lib PROPERTIES
        LINK_FLAGS "-lm"
        )


# Get proper shared-library behavior (where symbols are not necessarily
# resolved when the shared library is linked) on OS X.
if (APPLE)
    set_target_properties(BaggyBounds PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
            )
endif (APPLE)
