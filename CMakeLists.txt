cmake_minimum_required(VERSION 3.0)

project(ExecutableAnalyzer)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")
file(GLOB_RECURSE FOXSOURCES "src/*.cpp")
file(GLOB_RECURSE FOXSOURCESH "src/*.h")
file(GLOB_RECURSE FOXSOURCESHPP "src/*.hpp")

file(GLOB IMGUISOURCES "libs/imgui/imgui*.cpp")
set(FOXSOURCES "${FOXSOURCES};${PROJECT_SOURCE_DIR}/libs/imgui/backends/imgui_impl_opengl2.cpp")
set(FOXSOURCES "${FOXSOURCES};${PROJECT_SOURCE_DIR}/libs/imgui/backends/imgui_impl_glfw.cpp")
set(FOXSOURCES "${FOXSOURCES};${IMGUISOURCES}")
set(FOXSOURCES "${FOXSOURCES};${FOXSOURCESH}")
set(FOXSOURCES "${FOXSOURCES};${FOXSOURCESHPP}")

message("FOXSOURCES contains ${FOXSOURCES}")

include_directories("${PROJECT_SOURCE_DIR}/libs/imgui")
include_directories("${PROJECT_SOURCE_DIR}/libs/glfw/include")
include_directories("${PROJECT_SOURCE_DIR}/libs/imgui/backends")

include_directories("${PROJECT_SOURCE_DIR}/libs/digestpp")

#dont build GLFW  docs tests exmaples
set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)

add_subdirectory("libs/glfw/")

#look for opengl
find_package(OpenGL REQUIRED)

add_executable(${PROJECT_NAME} ${FOXSOURCES})
target_link_libraries(${CMAKE_PROJECT_NAME} glfw)

if(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
  target_link_libraries(${CMAKE_PROJECT_NAME} opengl32.lib gdi32.lib shell32.lib)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
  target_link_libraries(${CMAKE_PROJECT_NAME} GL)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
  SET(CMAKE_XCODE_ATTRIBUTE_CLANG_CXX_LIBRARY "libc++")
  target_link_libraries(${CMAKE_PROJECT_NAME} "-framework OpenGL")
  target_link_libraries(${CMAKE_PROJECT_NAME} "-framework Cocoa")
  target_link_libraries(${CMAKE_PROJECT_NAME} "-framework IOKit")
  target_link_libraries(${CMAKE_PROJECT_NAME} "-framework CoreVideo")
endif()

#foxlib opengl32.lib gdi32.lib shell32.lib
