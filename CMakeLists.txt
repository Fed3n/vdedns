cmake_minimum_required(VERSION 3.13)
project(VdeDNS  VERSION 1.0
                DESCRIPTION "Proxy DNS for IoTh"
                LANGUAGES C)
set(CMAKE_BUILD_TYPE Debug)

file(GLOB SOURCES "./*.c")

set(REQLIBS ioth iothdns iothconf iothaddr pthread config)

include(GNUInstallDirs)
include(CheckIncludeFile)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FORTIFY_SOURCE=2 -O2 -Wall -pedantic")

foreach(LIB IN LISTS REQLIBS)
    find_library(HAVE_${LIB} ${LIB})
    if(NOT HAVE_${LIB})
        message(FATAL_ERROR "Could not find library lib${LIB}")
    endif()
endforeach(LIB)

set(REQHEAD ioth.h iothdns.h iothconf.h iothaddr.h pthread.h libconfig.h)

foreach(HEAD IN LISTS REQHEAD)
    check_include_file(${HEAD} HAVE_${HEAD})
    if(NOT HAVE_${HEAD})
        message(FATAL_ERROR "Could not find header ${HEAD}")
    endif()
endforeach(HEAD)


include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_executable(vdedns ${SOURCES})
target_link_libraries(vdedns ${REQLIBS})

add_subdirectory(man)
