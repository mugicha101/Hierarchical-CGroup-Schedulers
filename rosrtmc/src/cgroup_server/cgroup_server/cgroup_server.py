import rclpy
from rclpy.node import Node
from rclpy.parameter import Parameter
import threading
import queue
import sys

from cgroup_server_interfaces.srv import RequestCgroup
from cgroup_server.sched_manager import SchedManager
from std_msgs.msg import String

# node for managing the cgroup hierarchy via a sched_manager.py instance
# as cgroup hierarchy setup is part of initialization process, not optimized for performance
# sched_manager.py can be used as a standalone CLI tool
# to interface with the active sched_manager instance, use the following topics:
#  - publish to sched_manager_input topic with the same commands as the CLI tool
#  - read from sched_manager_output topic to receive results of the commands (only from sched_manager_input commands, not from the service calls)
# to create or request a cgroup, use the request_cgroup service (does not attach policies)
# to setup hierarchy, pass in a config file path via the "config_path" parameter
# NOTE: because SchedManager changes interrupt handling, this node should be run on its own process

class CgroupServer(Node):

    def __init__(self):
      super().__init__('cgroup_server')
      self.declare_parameter("scx_build_path", Parameter.Type.STRING)
      self.declare_parameter("config_path", "")

      self.srv = self.create_service(RequestCgroup, 'request_cgroup', self.handle_request_cgroup)
      self.sched_manager_input_sub = self.create_subscription(String, 'sched_manager_input', self.sched_manager_input_handler, 10)
      self.sched_manager_output_pub = self.create_publisher(String, 'sched_manager_output', 10)
      self.cmd_queue = queue.Queue()
      self.res_queue = queue.Queue()
      self.sched_manager_lock = threading.Lock()

      scx_build_path = self.get_parameter("scx_build_path").get_parameter_value().string_value
      self.sched_manager_thread = threading.Thread(
        target=self.sched_manager_thread_func,
        args=(self.cmd_queue, self.res_queue, self.sched_manager_lock, scx_build_path)
      )
      self.sched_manager_thread.start()
      
      succ, _ = self.sched_manager_cmd("ack 1")
      assert succ, "Failed to communicate set ACK mode for sched_manager"
      self.get_logger().info('Cgroup Server is ready.')

      config_path = self.get_parameter("config_path").get_parameter_value().string_value
      if len(config_path) != 0:
        succ, res = self.sched_manager_cmd(f"load_config {config_path}")
        if not succ:
          self.get_logger().error(f"Failed to load config from {config_path}: {res}")
          sys.exit(1)

    def sched_manager_thread_func(self, cmd_queue, res_queue, lock, scx_build_path):
      sched_manager = SchedManager(scx_build_path=scx_build_path, output_queue=res_queue)
      while rclpy.ok():
        cmd = cmd_queue.get()
        print(f"Sched Manager thread received command: {cmd}")
        if sched_manager.onecmd(cmd):
          return

    def sched_manager_cmd(self, cmd, topic_output=False):
      with self.sched_manager_lock:
        assert self.sched_manager_thread.is_alive(), "Sched Manager thread has stopped unexpectedly"
        assert self.res_queue.empty(), "Result queue should be empty before sending a new command"
        self.cmd_queue.put(cmd)

        lines = []
        while True:
          res = self.res_queue.get()
          lines.append(res)
          if topic_output:
            self.sched_manager_output_pub.publish(String(data=res))
          if res.startswith("ACK"):
            return True, lines
          elif res.startswith("ERR:"):
            self.get_logger().error("Error from sched_manager: " + res)
            return False, lines

    def sched_manager_input_handler(self, msg):
      cmd = msg.data
      self.get_logger().info(f"Received command for sched_manager: {cmd}")
      self.sched_manager_cmd(cmd, topic_output=True)

    def handle_request_cgroup(self, request, response):
      # check if already exists
      succ, res = self.sched_manager_cmd(f"sched {request.cgroup_path}")
      if not succ:
        response.success = False
        return
      if "no cgroup" not in "\n".join(res):
        response.success = True
        return

      # attach
      succ, res = self.sched_manager_cmd(f"attach none {request.cgroup_path}")
      response.success = succ

      return response

    def exit(self):
      self.sched_manager_cmd("exit")

def main(args=None):
  rclpy.init(args=args)
  cgroup_server = CgroupServer()
  try:
    rclpy.spin(cgroup_server)
  except KeyboardInterrupt:
    pass
  cgroup_server.exit()
  cgroup_server.destroy_node()
  if rclpy.ok():
    rclpy.shutdown()

if __name__ == '__main__':
  main()