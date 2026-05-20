cmake_minimum_required(VERSION 3.8)
project(hierarchical_components)

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# find dependencies
find_package(ament_cmake REQUIRED)
# uncomment the following section in order to fill in
# further dependencies manually.
# find_package(<dependency> REQUIRED)

find_package(rclcpp REQUIRED)
find_package(rclcpp_components REQUIRED)
find_package(multithreaded_events_executor REQUIRED)
# find_package(std_msgs REQUIRED)

add_executable(
  hierarchical_component_container
  src/hierarchical_component_container.cpp
)
# target_include_directories(hierarchical_components PUBLIC include)
# target_link_libraries(hierarchical_component_container multithreaded_events_executor component_manager rclcpp)
ament_target_dependencies(hierarchical_component_container rclcpp multithreaded_events_executor rclcpp_components)
# Install executables
# install(
#   TARGETS hierarchical_component_container
#   RUNTIME DESTINATION lib/${PROJECT_NAME}
# )

# install(TARGETS
#   hierarchical_component_container
#   EXPORT export_${PROJECT_NAME}
#   ARCHIVE DESTINATION lib
#   LIBRARY DESTINATION lib
#   RUNTIME DESTINATION bin)

install(TARGETS hierarchical_component_container
    DESTINATION lib/${PROJECT_NAME})

# install(DIRECTORY include/
#   DESTINATION include/${PROJECT_NAME})

# ament_export_libraries(multithreaded_events_executor)
# ament_export_targets(export_${PROJECT_NAME})
# ament_export_dependencies(rclcpp)

if(BUILD_TESTING)
  find_package(ament_lint_auto REQUIRED)
  # the following line skips the linter which checks for copyrights
  # comment the line when a copyright and license is added to all source files
  set(ament_cmake_copyright_FOUND TRUE)
  # the following line skips cpplint (only works in a git repo)
  # comment the line when this package is in a git repo and when
  # a copyright and license is added to all source files
  set(ament_cmake_cpplint_FOUND TRUE)
  ament_lint_auto_find_test_dependencies()
endif()

ament_package()
