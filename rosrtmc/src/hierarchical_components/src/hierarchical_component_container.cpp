#include "multithreaded_events_executor/multithreaded_events_executor.hpp"
#include "rclcpp_components/component_manager.hpp"
#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <iostream>
#include <linux/sched.h>
#include <memory>
#include <cerrno>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/wait.h> // For waitpid() and waitid()
#include <fstream>
#include <string>

// Returns the cgroup path string, or an empty string on failure
std::string get_process_cgroup_path(int pid) {
    std::string proc_filepath;
    
    if (pid <= 0) {
        proc_filepath = "/proc/self/cgroup";
    } else {
        proc_filepath = "/proc/" + std::to_string(pid) + "/cgroup";
    }

    std::ifstream infile(proc_filepath);
    if (!infile.is_open()) {
        return ""; // Could not open the proc file
    }

    std::string line;
    // Read the file line by line
    while (std::getline(infile, line)) {
        // Find the last colon separator in the line
        size_t last_colon = line.rfind(':');
        
        if (last_colon != std::string::npos) {
            // Extract everything after the last colon
            return line.substr(last_colon + 1);
        }
    }

    return ""; // No valid cgroup path found
}

static volatile int exit_req;

static void siginit_handler(int signum)
{
  exit_req = 1;
}

int main(int argc, char *argv[]) {

  signal(SIGINT, siginit_handler);
  signal(SIGTERM, siginit_handler);

  if (argc < 3)
  {
    std::cerr << "Usage: " << argv[0] << " <num_threads> <cgroup_path>\n";
    return 1;
  }

  std::string cgroup_path = argv[2];

  /// Create cgroup for component
  std::cout << "Opening cgroup path: " << cgroup_path << std::endl;
  int cg_fd = open(cgroup_path.c_str(), O_RDONLY | O_DIRECTORY);
  if (cg_fd < 0) {
    std::cerr << "Failed to create cgroup: " << strerror(errno) << std::endl;
    return 1;
  }

  struct clone_args args = {0};
  args.flags = CLONE_INTO_CGROUP;
  args.cgroup = cg_fd;
  args.exit_signal = SIGCHLD;

  std::cout << "Cloning process into cgroup \"" << cgroup_path << "\" using clone3()...\n";
  pid_t pid = syscall(SYS_clone3, &args, sizeof(args));
  close(cg_fd);

  if (pid < 0) {
    std::cerr << "Failed to clone process into cgroup: " << strerror(errno)
              << std::endl;
    return 1;
  }

  if (pid == 0) {
    // --- CHILD PROCESS EXECUTION ---
    std::cout << "[CHILD] Hello from the child process! PID: " << getpid()
              << "\n";
    std::string self_path = get_process_cgroup_path(0);
    if (!self_path.empty()) {
        std::cout << "Child process cgroup path: \"" << self_path << "\"\n";
    } else {
        std::cerr << "Failed to read child process cgroup.\n";
    }

    /// Component container with a single-threaded executor.
    rclcpp::init(argc, argv);
    rosrtmc::executors::MultiThreadedEventsExecutor::SharedPtr exec = nullptr;
    auto node = std::make_shared<rclcpp_components::ComponentManager>();
    int64_t num_threads = 1;
    // if (node->has_parameter("thread_num")) {
    //     num_threads = node->get_parameter("thread_num").as_int();
    // }
    if (argc > 1) {
        num_threads = std::stoll(argv[1]);
    }
    std::cout << "Launching executor with " << num_threads << " threads." << std::endl;
    exec = std::make_shared<rosrtmc::executors::MultiThreadedEventsExecutor>(num_threads);
    node->set_executor(exec);
    exec->add_node(node);
    std::cout << "Spinning executor..." << std::endl;
    exec->spin();
    return 0;
  }
 
  std::cout << "[PARENT] Waiting via waitid() using PIDFD " << pid << "...\n";
  std::string self_path = get_process_cgroup_path(0);
    if (!self_path.empty()) {
        std::cout << "Parent process cgroup path: \"" << self_path << "\"\n";
    } else {
        std::cerr << "Failed to read parent process cgroup.\n";
    }

  while(!exit_req)
  {
    sleep(1);
  }
  kill(pid, SIGKILL);
  waitpid(pid, NULL, 0);
}
