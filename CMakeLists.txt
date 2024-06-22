project(SmartMonitor)
cmake_minimum_required(VERSION 3.2)

include(GNUInstallDirs)
include_directories("/usr/local/include")
find_package(LLVM 10 REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LT_LLVM_INSTALL_DIR}")

add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})
link_directories(${LLVM_LIBRARY_DIRS})


option(USE_SEA_DSA "Use sea-dsa points to analysis" OFF)


# Use the same C++ standard as LLVM does
set(CMAKE_CXX_STANDARD 17 CACHE STRING "")

list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)

find_library(NEO4J_CLIENT neo4j-client)

# LLVM is normally built without RTTI. Be consistent with that.
if (NOT LLVM_ENABLE_RTTI)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
endif ()

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall\
    -fdiagnostics-color=always -g -Wno-everything -lstdc++fs")

# Removed this flag -lstdc++fs
llvm_map_components_to_libnames(REQ_LLVM_LIBRARIES ${LLVM_TARGETS_TO_BUILD}
        all asmparser core linker bitreader irreader ipo scalaropts
        analysis support
        )

add_subdirectory(CostEstimation)
add_subdirectory(Instrumentation)
add_subdirectory(Utilities)
add_subdirectory(SecurityImpactAnalysis)
cmake_policy(SET CMP0079 NEW)




