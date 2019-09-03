cmake_minimum_required(VERSION 2.8)
project(pds)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
add_definitions(-std=c++11)

find_package(Threads REQUIRED)
find_package(PCAP REQUIRED)

include_directories(${PCAP_INCLUDE_DIR})

set(SRC_LIBS addr.h addr.cpp netlib.h netlib.cpp pcap.h pcap.cpp
             checksum.h checksum.cpp headers.h types.h exceptions.h
             exceptions.cpp)

add_executable(pds-scanner ${SRC_LIBS} pds-scaner.cpp arpscan.h arpscan.cpp
                           ndscan.h ndscan.cpp)
target_link_libraries(pds-scanner ${PCAP_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

add_executable(pds-spoof ${SRC_LIBS} pds-spoof.cpp spoof.h spoof.cpp arpspoof.h
                         arpspoof.cpp ndspoof.h ndspoof.cpp ${SRC_LIBS})
target_link_libraries(pds-spoof ${PCAP_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
