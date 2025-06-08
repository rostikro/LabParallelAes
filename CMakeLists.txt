cmake_minimum_required(VERSION 3.31)
project(LabMPIAes)

set(CMAKE_CXX_STANDARD 26)

# MS-MPI
set(MPI_HOME "C:/Program Files (x86)/Microsoft SDKs/MPI")
set(MPI_INCLUDE_PATH "${MPI_HOME}/Include")
set(MPI_STATIC_LIB "${MPI_HOME}/Lib/x64/msmpi.lib")

find_package(OpenSSL REQUIRED)

add_executable(mpi mpi.cpp
        common.cpp
        common.h
)

target_include_directories(mpi PRIVATE ${MPI_INCLUDE_PATH})

target_link_libraries(mpi PRIVATE ${MPI_STATIC_LIB})
target_link_libraries(mpi PRIVATE OpenSSL::Crypto)


add_executable(test test.cpp
        common.cpp
        common.h)

target_link_libraries(test PRIVATE OpenSSL::Crypto)
