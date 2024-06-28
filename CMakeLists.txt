cmake_minimum_required(VERSION 3.10)

project(SteganoWhat VERSION 1.0)
set(CLIENT_EXEC_NAME client)

set(LIBRARY_NAME steganowhat_lib)
set(LIBRARY_NAME_SHARED steganowhat_lib_shared)
set(LIBRARY_NAME_TA steganowhat_lib_ta)

# turn on gdb
set(CMAKE_BUILD_TYPE Debug)

set( OpenCV_DIR "../build" )
option( OpenCV_STATIC OFF )
find_package( OpenCV REQUIRED )

# Set Static Link Runtime Library
if( OpenCV_STATIC )
  foreach( flag_var
           CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
           CMAKE_C_FLAGS_MINSIZEREL CMAKE_C_FLAGS_RELWITHDEBINFO
           CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
           CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO )
    if( ${flag_var} MATCHES "/MD" )
      string( REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}" )
    endif()
  endforeach()
endif()

# Additional Include Directories
include_directories( ${OpenCV_INCLUDE_DIRS} )
# Additional Library Directories
link_directories( ${OpenCV_LIB_DIR} )
# Additional Dependencies
# target_link_libraries( client ${OpenCV_LIBS} )

# packages
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
include(Boost)
# include(Cryptopp)
include(CTest)
include(Doctest)
include(Documentation)
include(Warnings)
include(Curses)

# add shared libraries
set(SOURCES_SHARED
  src-shared/messages.cxx
  src-shared/logger.cxx
  src-shared/util.cxx)
add_library(${LIBRARY_NAME_SHARED} ${SOURCES_SHARED})
target_include_directories(${LIBRARY_NAME_SHARED} PUBLIC ${PROJECT_SOURCE_DIR}/include-shared)
target_link_libraries(${LIBRARY_NAME_SHARED} PUBLIC doctest)
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE cryptopp)
# target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE cryptopp-shared)
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE ${Boost_LIBRARIES})
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE ${CURSES_LIBRARIES})
target_link_libraries( ${LIBRARY_NAME_SHARED} PRIVATE ${OpenCV_LIBS} )

# add student libraries
set(SOURCES
  src/pkg/client.cxx
  src/drivers/cli_driver.cxx
  src/drivers/crypto_driver.cxx
  src/drivers/network_driver.cxx
  src/drivers/stegano_driver.cxx)
add_library(${LIBRARY_NAME} ${SOURCES})
target_include_directories(${LIBRARY_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include-shared ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(${LIBRARY_NAME} PRIVATE ${LIBRARY_NAME_SHARED})

# # add ta libraries
# if ( "$ENV{CS1515_TA_MODE}" STREQUAL "on" )
#   set(SOURCES_TA
#     src-ta/drivers/cli_driver.cxx
#     src-ta/drivers/crypto_driver.cxx
#     src-ta/drivers/network_driver.cxx)
#   add_library(${LIBRARY_NAME_TA} ${SOURCES_TA})
#   target_include_directories(${LIBRARY_NAME_TA} PUBLIC ${PROJECT_SOURCE_DIR}/include-shared ${PROJECT_SOURCE_DIR}/include-ta)
#   target_link_libraries(${LIBRARY_NAME_TA} PRIVATE ${LIBRARY_NAME_SHARED})
# endif()

# add garbler executables
# if ( "$ENV{CS1515_TA_MODE}" STREQUAL "on" )
#   add_executable(${CLIENT_EXEC_NAME} src-ta/cmd/client.cxx)
#   target_link_libraries(${CLIENT_EXEC_NAME} PRIVATE ${LIBRARY_NAME_TA})
# else()
#   add_executable(${CLIENT_EXEC_NAME} src/cmd/main.cxx)
#   target_link_libraries(${CLIENT_EXEC_NAME} PRIVATE ${LIBRARY_NAME})
# endif()


add_executable(${CLIENT_EXEC_NAME} src/cmd/main.cxx)
target_link_libraries(${CLIENT_EXEC_NAME} PRIVATE ${LIBRARY_NAME})

# # add evaluator executables
# if ( "$ENV{CS1515_TA_MODE}" STREQUAL "on" )
#   add_executable(${EVALUATOR_EXEC_NAME} src-ta/cmd/evaluator.cxx)
#   target_link_libraries(${EVALUATOR_EXEC_NAME} PRIVATE ${LIBRARY_NAME_TA})
# else()
#   add_executable(${EVALUATOR_EXEC_NAME} src/cmd/evaluator.cxx)
#   target_link_libraries(${EVALUATOR_EXEC_NAME} PRIVATE ${LIBRARY_NAME})
# endif()

# add ot test executables
# if ( "$ENV{CS1515_TA_MODE}" STREQUAL "on" )
#   add_executable(${OTTEST_EXEC_NAME} src-ta/cmd/ot_test.cxx)
#   target_link_libraries(${OTTEST_EXEC_NAME} PRIVATE ${LIBRARY_NAME_TA})
# else()
#   add_executable(${OTTEST_EXEC_NAME} src/cmd/ot_test.cxx)
#   target_link_libraries(${OTTEST_EXEC_NAME} PRIVATE ${LIBRARY_NAME})
# endif()

# properties
set_target_properties(
  ${LIBRARY_NAME}
  ${CLIENT_EXEC_NAME}
  # ${OTTEST_EXEC_NAME}
    PROPERTIES
      CXX_STANDARD 20
      CXX_STANDARD_REQUIRED YES
      CXX_EXTENSIONS YES
)

# # ta properties
# if ( "$ENV{CS1515_TA_MODE}" STREQUAL "on" )
#   set_target_properties(
#     ${LIBRARY_NAME_TA}
#         PROPERTIES
#           CXX_STANDARD 20
#           CXX_STANDARD_REQUIRED YES
#           CXX_EXTENSIONS YES
#   )
# endif()

# add tests
# add_subdirectory(test)
# add_custom_target(check ./test.sh)





