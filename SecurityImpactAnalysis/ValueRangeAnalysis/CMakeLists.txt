find_library(NEO4J_CLIENT neo4j-client)
include_directories("/usr/local/include")

configure_file(config.h.in config.h @ONLY)

# Check if MY_VERSION is defined
if(USE_SEA_DSA)
    message(STATUS "Using sea-dsa for Points to analysis")
    include_directories(sea-dsa/include)
    add_subdirectory(sea-dsa)
else()
    message(STATUS "Using SVF for Points to analysis")
    include_directories("${CMAKE_SOURCE_DIR}/../SVF/include")
endif()


# # Compiler flag
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fno-rtti -Wall -fdiagnostics-color=always  -lstdc++fs")

# set(CMAKE_CXX_STANDARD 17 CACHE STRING "")


# Dataguard : nescheck + Value range
add_library(NesCheck MODULE
        AnalysisState.cpp
        AnalysisState.hpp
        NesCheck.cpp
        ValueRangeAnalysis.cpp
        ValueRangeAnalysis.hh
        DataflowAnalysis.hh
        PTAWrapper.hh
        PTAWrapper.cpp
        LLVMEssentials.hh
        GraphConstants.h
)


# value range + db and points to code + Coverage code (gcov)
add_executable(valueRange
        GCOV.cpp
        GCOV.h
        CoverageUtilities.cpp
        CoverageUtilities.hh
        DataflowAnalysis.hh
        PTAWrapper.hh
        PTAWrapper.cpp
        GraphConstants.h
        ValueRangeAnalysis.hh
        ValueRangeStandAlone.cpp
)

llvm_map_components_to_libnames(REQ_LLVM_LIBRARIES ${LLVM_TARGETS_TO_BUILD}
        asmparser core linker bitreader irreader ipo scalaropts
        analysis support
)



if(USE_SEA_DSA)
        target_link_libraries(NesCheck PUBLIC "${CMAKE_SOURCE_DIR}/sea-dsa/build/lib/libSeaDsaAnalysis.a" "${NEO4J_CLIENT}")
        target_link_libraries(valueRange ${REQ_LLVM_LIBRARIES} "${NEO4J_CLIENT}" "${CMAKE_SOURCE_DIR}/sea-dsa/build/lib/libSeaDsaAnalysis.a" stdc++fs)
else()
        target_link_libraries(NesCheck PUBLIC "${CMAKE_SOURCE_DIR}/SVF/lib/libSvf.a" "${NEO4J_CLIENT}")
        target_link_libraries(valueRange ${REQ_LLVM_LIBRARIES} "${NEO4J_CLIENT}" "${CMAKE_SOURCE_DIR}/SVF/lib/libSvf.a" stdc++fs)
endif()