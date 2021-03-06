cmake_minimum_required(VERSION 2.8)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(kernel_hooker)
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -Wno-unused-variable -Wno-implicit-function-declaration -O3 -nostdlib")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions")

add_executable(kernel_hooker
  kernel.c
)

target_link_libraries(kernel_hooker
  taihenForKernel_stub
  taihenModuleUtils_stub
  SceThreadmgrForDriver_stub
  SceModulemgrForKernel_stub
  SceIofilemgrForDriver_stub
  SceSysmemForDriver_stub
  SceSysclibForDriver_stub
  ScePowerForDriver_stub
)

vita_create_self(kernel_hooker.skprx kernel_hooker CONFIG exports.yml UNSAFE)

vita_create_stubs(stubs kernel_hooker ${CMAKE_SOURCE_DIR}/exports.yml KERNEL)
