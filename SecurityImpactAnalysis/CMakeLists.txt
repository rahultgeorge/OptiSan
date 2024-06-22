# cmake_minimum_required(VERSION 3.4)
# project(SecurityImpactAnalysis)

# # set(CMAKE_CXX_STANDARD 17)

# set(LLVM_DIR,${LLVM_DIR})
# find_package(LLVM 10 REQUIRED CONFIG)
# message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
# message(STATUS "Using LLVMConfig.cmake in: ${LT_LLVM_INSTALL_DIR}")

# add_definitions(${LLVM_DEFINITIONS})
# include_directories(${LLVM_INCLUDE_DIRS})
# link_directories(${LLVM_LIBRARY_DIRS})

# # Use the same C++ standard as LLVM does
# list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
# include(AddLLVM)

# # LLVM is normally built without RTTI. Be consistent with that.
# if(NOT LLVM_ENABLE_RTTI)
#     set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
# endif()

# find_library(NEO4J_CLIENT neo4j-client)

# # Compiler flags
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall\
#     -fdiagnostics-color=always -g -O2")

include_directories("program-dependence-graph/include")
add_subdirectory(program-dependence-graph)

include_directories("${CMAKE_SOURCE_DIR}/SVF/include")

add_subdirectory(ValueRangeAnalysis)

# Removed this flag -lstdc++fs
# llvm_map_components_to_libnames(REQ_LLVM_LIBRARIES ${LLVM_TARGETS_TO_BUILD}
# all asmparser core linker bitreader irreader ipo scalaropts
# analysis support
# )


# Computes unsafe operations using VR results
add_library(UnsafeMemoryOperationsAnalysis MODULE
    MemorySafetyResults.cpp
    FunctionScanPass.cpp
    SpatialMemorySafetyAnalysis.cpp
)

# Computes targets
add_library(SecurityImpactAnalysis MODULE
    MemorySafetyResults.cpp
    ReachabilityGraph.cpp
    IntraTargetAnalysisPass.cpp
    FunctionScanPass.cpp
    UsableTargetsAnalysis.cpp
)



if(APPLE)
    set_target_properties(SecurityImpactAnalysis PROPERTIES LINK_FLAGS "-undefined dynamic_lookup")
endif(APPLE)

# target_link_libraries(SecurityImpactAnalysis "${CMAKE_CURRENT_SOURCE_DIR}/SVF/lib/libSvf.a" "${NEO4J_CLIENT}")
# target_link_libraries(SecurityImpactAnalysis PUBLIC  "${CMAKE_CURRENT_SOURCE_DIR}/SVF/lib/libSvf.a" "${CMAKE_CURRENT_SOURCE_DIR}/program-dependence-graph/libpdg.so" "${NEO4J_CLIENT}")
target_link_libraries(SecurityImpactAnalysis PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/program-dependence-graph/libpdg.so" "${NEO4J_CLIENT}")


# target_link_libraries(SecurityImpactAnalysis PUBLIC  "${NEO4J_CLIENT}")
target_link_libraries(UnsafeMemoryOperationsAnalysis PUBLIC "${NEO4J_CLIENT}")
