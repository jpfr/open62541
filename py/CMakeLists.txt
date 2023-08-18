find_package(Python3 REQUIRED COMPONENTS Interpreter Development)

file(MAKE_DIRECTORY "${PROJECT_BINARY_DIR}/src_generated/py")

add_custom_command(
    OUTPUT ${PROJECT_BINARY_DIR}/src_generated/py/open62541_ext.c ${PROJECT_BINARY_DIR}/src_generated/py/open62541_ext.h
    COMMAND ${Python3_EXECUTABLE} -m cython -3 -o ${PROJECT_BINARY_DIR}/src_generated/py/open62541_ext.c ${CMAKE_CURRENT_SOURCE_DIR}/open62541_ext.pyx
    WORKING_DIRECTORY ${PROJECT_BINARY_DIR}/src_generated/py
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/open62541_ext.pyx
)

add_library(open62541_ext SHARED
    ${PROJECT_BINARY_DIR}/src_generated/py/open62541_ext.c
)

target_link_libraries(open62541_ext PUBLIC Python3::Python)
target_include_directories(open62541_ext
    PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
      $<INSTALL_INTERFACE:include>
    PRIVATE
      ${PROJECT_BINARY_DIR}/src_generated/py
)
