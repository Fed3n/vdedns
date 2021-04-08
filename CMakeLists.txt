cmake_minimum_required(VERSION 3.10)
project(VdeDNS  VERSION 1.0
                DESCRIPTION "Proxy DNS for IoTh"
                LANGUAGES C)
set(CMAKE_BUILD_TYPE Debug)

file(GLOB SOURCES "./*.c")
set(LIBS -lioth -liothdns -liothconf -liothaddr -lpthread -lconfig)
 
add_executable(dns ${SOURCES})
target_link_libraries(dns ${LIBS})
