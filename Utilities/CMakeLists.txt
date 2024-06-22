include_directories("${CMAKE_SOURCE_DIR}/SVF/include")


add_library(DebugModulePass MODULE
        DebugModulePass.cpp
        DebugLocIDPass.cpp
        DebugLocIDPass.hh)

add_library(UnsafePtrAnalyzer MODULE
        PTAWrapper.hh
        PTAWrapper.cpp
        FunctionScanPass.cpp
        FunctionScanPass.hh        
        UnsafePtrAnalyzer.cpp
        )


target_link_libraries(DebugModulePass "${NEO4J_CLIENT}")
target_link_libraries(UnsafePtrAnalyzer PUBLIC "${NEO4J_CLIENT}" "${CMAKE_SOURCE_DIR}/SVF/lib/libSvf.a")


#
# OS X-specific configuration
#
if (APPLE)
    set_target_properties(DebugModulePass PROPERTIES LINK_FLAGS "-undefined dynamic_lookup")
    set_target_properties(UnsafePtrAnalyzer PROPERTIES LINK_FLAGS "-undefined dynamic_lookup")

endif (APPLE)