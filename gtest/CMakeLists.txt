find_package(Threads)

add_library(gtest STATIC src/gtest-all.cc)
target_link_libraries(gtest PUBLIC Threads::Threads)
target_include_directories(gtest PRIVATE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
target_include_directories(gtest PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)


