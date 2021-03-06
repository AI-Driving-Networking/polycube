include(${PROJECT_SOURCE_DIR}/cmake/LoadFileAsVariable.cmake)

aux_source_directory(serializer SERIALIZER_SOURCES)
aux_source_directory(api API_SOURCES)
aux_source_directory(base BASE_SOURCES)

include_directories(serializer)

find_library(PCAP_LIBRARY
        NAMES pcap)

if (NOT DEFINED POLYCUBE_STANDALONE_SERVICE OR POLYCUBE_STANDALONE_SERVICE)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(POLYCUBE libpolycube)
  include_directories(${POLYCUBE_INCLUDE_DIRS})
endif(NOT DEFINED POLYCUBE_STANDALONE_SERVICE OR POLYCUBE_STANDALONE_SERVICE)

# Needed to load files as variables
include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_library(pcn-packetcapture SHARED
  ${SERIALIZER_SOURCES}
  ${API_SOURCES}
  ${BASE_SOURCES}
  Globalheader.cpp
  Packet.cpp
  Packetcapture.cpp
  Packetcapture-lib.cpp
  cbpf2c.cpp)

# load ebpf datapath code a variable
load_file_as_variable(pcn-packetcapture
  Packetcapture_dp_ingress.c
  packetcapture_code_ingress)
load_file_as_variable(pcn-packetcapture
  Packetcapture_dp_egress.c
  packetcapture_code_egress) 

# load datamodel in a variable
load_file_as_variable(pcn-packetcapture
  ../datamodel/packetcapture.yang
  packetcapture_datamodel)

target_link_libraries(pcn-packetcapture ${POLYCUBE_LIBRARIES})
target_link_libraries(pcn-packetcapture ${PCAP_LIBRARY})

# Specify shared library install directory

set(CMAKE_INSTALL_LIBDIR /usr/lib)
set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARY})

install(
    TARGETS
    pcn-packetcapture
    DESTINATION
    "${CMAKE_INSTALL_LIBDIR}"
)
