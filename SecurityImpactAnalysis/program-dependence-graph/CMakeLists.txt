include_directories("include")
include_directories("src")
include_directories("${CMAKE_SOURCE_DIR}/SVF/include")

file(GLOB SOURCES "src/*.cpp")
file(GLOB HEADERS "include/*.hh")

add_library(pdg MODULE
    ${HEADERS}
    ${SOURCES}
)

# add_library(pdg_shared STATIC ${SOURCES})

target_link_libraries(pdg PUBLIC "${CMAKE_SOURCE_DIR}/SVF/lib/libSvf.a")


