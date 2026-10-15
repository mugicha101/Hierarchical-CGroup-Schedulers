import rclpy
import os
from rclpy.node import Node
from std_msgs.msg import String
from rclpy.qos import QoSProfile, QoSReliabilityPolicy, QoSDurabilityPolicy
import sys
import time

def main():
  rclpy.init()
  qos_profile = QoSProfile(
    reliability=QoSReliabilityPolicy.RELIABLE,
    durability=QoSDurabilityPolicy.TRANSIENT_LOCAL,
    depth=10
  )
  node = rclpy.create_node(f"prompt_server_node_{os.getpid()}")
  pub = node.create_publisher(String, "sched_manager_input", qos_profile)
  def handle_output(msg):
    print(msg.data)
    if msg.data.startswith("ACK") or msg.data.startswith("ERR:"):
      node.destroy_node()
      rclpy.shutdown()

  sub = node.create_subscription(String, "sched_manager_output", handle_output, 10)
  while pub.get_subscription_count() == 0 or sub.get_publisher_count() == 0:
    print("Waiting for setup...")
    rclpy.spin_once(node, timeout_sec=0.5)

  print("Published...")
  cmd = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else ""
  pub.publish(String(data=cmd))
  rclpy.spin(node)

if __name__ == '__main__':
  main()