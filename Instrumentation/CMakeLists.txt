add_library(SanitizerHelperPass MODULE
        PreSanitizationHelperPass.cpp
        PostSanitizationHelperPass.cpp
        SanitizerHelperPass.hh
        FunctionScanPass.cpp
        FunctionScanPass.hh
        )



add_library(TurnOffChecks MODULE
        TurnOffChecks.cpp
        )


target_link_libraries(SanitizerHelperPass "${NEO4J_CLIENT}" stdc++fs)

#
# OS X-specific configuration
#
if (APPLE)
    set_target_properties(SanitizerHelperPass PROPERTIES LINK_FLAGS "-undefined dynamic_lookup")
endif (APPLE)