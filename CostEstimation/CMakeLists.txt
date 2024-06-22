add_library(CostEstimationPass MODULE
        CostEstimationPass.cpp
        CostEstimationFunctionPass.cpp
        EstimationPass.hh
        CoverageUtilities.cpp
        CoverageUtilities.hh
        FunctionScanPass.cpp
        FunctionScanPass.hh
        GCOV.cpp
        GCOV.h
        )



# STDC++ FS does not work on Apple (FIX COMMAND)
target_link_libraries(CostEstimationPass "${NEO4J_CLIENT}" stdc++fs)


#
# OS X-specific configuration
#
if (APPLE)
    set_target_properties(CostEstimationPass PROPERTIES LINK_FLAGS "-undefined dynamic_lookup")
endif (APPLE)


