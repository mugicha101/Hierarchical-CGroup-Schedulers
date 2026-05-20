#include <gtest/gtest.h>
#include "multithreaded_events_executor/multithreaded_events_executor.hpp"
#include "test_msgs/srv/empty.hpp"
#include "test_msgs/msg/empty.hpp"

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <iostream>

using namespace std::chrono_literals;

using rosrtmc::executors::MultiThreadedEventsExecutor;

class TestMultiThreadedEventsExecutor : public ::testing::Test
{
public:
  void SetUp()
  {
    rclcpp::init(0, nullptr);
  }

  void TearDown()
  {
    rclcpp::shutdown();
  }
};

TEST_F(TestMultiThreadedEventsExecutor, test_constructor)
{
    auto node = std::make_shared<rclcpp::Node>("node");

    bool msg_received = false;
    auto subscription = node->create_subscription<test_msgs::msg::Empty>(
    "topic", rclcpp::SensorDataQoS(),
    [&msg_received](test_msgs::msg::Empty::ConstSharedPtr msg)
    {
        (void)msg;
        msg_received = true;
    });

    auto publisher = node->create_publisher<test_msgs::msg::Empty>("topic", rclcpp::SensorDataQoS());

    MultiThreadedEventsExecutor executor(1);
    executor.add_node(node);
    executor.spin();

    auto msg = std::make_unique<test_msgs::msg::Empty>();
    publisher->publish(std::move(msg));

    // Wait some time for the subscription to receive the message
    auto start = std::chrono::high_resolution_clock::now();
    while (
        !msg_received &&
        (std::chrono::high_resolution_clock::now() - start < 1s)
    )
    {
    std::this_thread::sleep_for(25ms);
    }

    executor.cancel();
    executor.remove_node(node);

    EXPECT_TRUE(msg_received);
    std::cout << "Received message: " << std::boolalpha << msg_received << std::endl;
}

TEST_F(TestMultiThreadedEventsExecutor, multiple_threads)
{
    auto node = std::make_shared<rclcpp::Node>("node");

    std::atomic<int> msg_count{0};
    std::unordered_map<std::thread::id, std::unique_ptr<std::atomic<int>>> thread_counts;
    std::mutex thread_counts_mutex;

    auto subscription = node->create_subscription<test_msgs::msg::Empty>(
    "topic", rclcpp::SystemDefaultsQoS(),
    [&](test_msgs::msg::Empty::ConstSharedPtr msg)
    {
        (void)msg;
        msg_count.fetch_add(1);

        auto tid = std::this_thread::get_id();
        std::atomic<int>* counter;
        {
            std::lock_guard<std::mutex> lock(thread_counts_mutex);
            auto [it, inserted] = thread_counts.try_emplace(tid, std::make_unique<std::atomic<int>>(0));
            counter = it->second.get();
        }
        counter->fetch_add(1);
    });

    auto publisher = node->create_publisher<test_msgs::msg::Empty>("topic", rclcpp::SystemDefaultsQoS());

    MultiThreadedEventsExecutor executor(2);
    executor.add_node(node);
    executor.spin();

    for (int i = 0; i < 10; i++) {
      auto msg = std::make_unique<test_msgs::msg::Empty>();
      publisher->publish(std::move(msg));
      std::this_thread::sleep_for(50ms);
    }

    auto start = std::chrono::high_resolution_clock::now();
    while (
        msg_count.load() < 10 &&
        (std::chrono::high_resolution_clock::now() - start < 1s)
    )
    {
    std::this_thread::sleep_for(1s);
    }

    executor.cancel();
    executor.remove_node(node);

    EXPECT_EQ(msg_count.load(), 10);
    std::cout << "Total received: " << msg_count.load() << " / 10" << std::endl;
    for (const auto & [tid, count] : thread_counts) {
        std::cout << "  Thread " << tid << ": " << count->load() << " callbacks" << std::endl;
    }
}

TEST_F(TestMultiThreadedEventsExecutor, run_clients_servers)
{
  auto node = std::make_shared<rclcpp::Node>("node");

  std::atomic<int> requests_handled{0};
  std::atomic<int> responses_received{0};
  auto service =
    node->create_service<test_msgs::srv::Empty>(
    "service",
    [&requests_handled](
      const test_msgs::srv::Empty::Request::SharedPtr,
      test_msgs::srv::Empty::Response::SharedPtr)
    {
      requests_handled.fetch_add(1);
    });
  auto client1 = node->create_client<test_msgs::srv::Empty>("service");
  auto client2 = node->create_client<test_msgs::srv::Empty>("service");

  MultiThreadedEventsExecutor executor(10);
  executor.add_node(node);
  executor.spin();

  auto send_requests = [&responses_received](rclcpp::Client<test_msgs::srv::Empty>::SharedPtr client) {
    for (int i = 0; i < 5; i++) {
      auto request = std::make_shared<test_msgs::srv::Empty::Request>();
      client->async_send_request(
        request,
        [&responses_received](rclcpp::Client<test_msgs::srv::Empty>::SharedFuture result_future) {
          (void)result_future;
          responses_received.fetch_add(1);
        });
      std::this_thread::sleep_for(50ms);
    }
  };

  send_requests(client1);
  send_requests(client2);

  auto start = std::chrono::steady_clock::now();
  while (
    responses_received.load() < 10 &&
    (std::chrono::steady_clock::now() - start < 2s))
  {
    std::this_thread::sleep_for(5ms);
  }

  executor.cancel();
  executor.remove_node(node);

  EXPECT_EQ(requests_handled.load(), 10);
  EXPECT_EQ(responses_received.load(), 10);
  std::cout << "Requests handled: " << requests_handled.load() << " / 10" << std::endl;
  std::cout << "Responses received: " << responses_received.load() << " / 10" << std::endl;
}

TEST_F(TestMultiThreadedEventsExecutor, multiple_pub_sub)
{
  auto node = std::make_shared<rclcpp::Node>("node");

  std::atomic<int> total_callbacks{0};
  const int num_topics = 5;
  const int subs_per_topic = 2;
  const int msgs_per_pub = 5;
  const int expected_callbacks = num_topics * subs_per_topic * msgs_per_pub;

  std::vector<rclcpp::Publisher<test_msgs::msg::Empty>::SharedPtr> publishers;
  std::vector<rclcpp::Subscription<test_msgs::msg::Empty>::SharedPtr> subscriptions;

  for (int t = 0; t < num_topics; t++) {
    std::string topic = "topic_" + std::to_string(t);
    publishers.push_back(
      node->create_publisher<test_msgs::msg::Empty>(topic, rclcpp::SystemDefaultsQoS()));

    for (int s = 0; s < subs_per_topic; s++) {
      subscriptions.push_back(
        node->create_subscription<test_msgs::msg::Empty>(
        topic, rclcpp::SystemDefaultsQoS(),
        [&total_callbacks](test_msgs::msg::Empty::ConstSharedPtr msg) {
          (void)msg;
          total_callbacks.fetch_add(1);
        }));
    }
  }

  MultiThreadedEventsExecutor executor(10);
  executor.add_node(node);
  executor.spin();

  for (int i = 0; i < msgs_per_pub; i++) {
    for (int t = 0; t < num_topics; t++) {
      auto msg = std::make_unique<test_msgs::msg::Empty>();
      publishers[t]->publish(std::move(msg));
    }
    std::this_thread::sleep_for(50ms);
  }

  auto start = std::chrono::steady_clock::now();
  while (
    total_callbacks.load() < expected_callbacks &&
    (std::chrono::steady_clock::now() - start < 3s))
  {
    std::this_thread::sleep_for(5ms);
  }

  executor.cancel();
  executor.remove_node(node);

  EXPECT_EQ(total_callbacks.load(), expected_callbacks);
  std::cout << "Callbacks completed: " << total_callbacks.load() << " / " << expected_callbacks << std::endl;
}

TEST_F(TestMultiThreadedEventsExecutor, two_nodes_pub_sub)
{
  auto node1 = std::make_shared<rclcpp::Node>("node1");
  auto node2 = std::make_shared<rclcpp::Node>("node2");

  std::atomic<int> total_callbacks{0};

  std::vector<rclcpp::Subscription<test_msgs::msg::Empty>::SharedPtr> subs1, subs2;
  const int num_subs_per_node = 2;
  for (int i = 0; i < num_subs_per_node; i++) 
  {
    subs1.emplace_back(node1->create_subscription<test_msgs::msg::Empty>(
        "topic", rclcpp::SystemDefaultsQoS(),
        [&](test_msgs::msg::Empty::ConstSharedPtr msg) {
          (void)msg;
          total_callbacks.fetch_add(1);
        }));
    subs2.emplace_back(node2->create_subscription<test_msgs::msg::Empty>(
        "topic", rclcpp::SystemDefaultsQoS(),
        [&](test_msgs::msg::Empty::ConstSharedPtr msg) {
          (void)msg;
          total_callbacks.fetch_add(1);
        }));
  }

  std::vector<rclcpp::Publisher<test_msgs::msg::Empty>::SharedPtr> pubs1, pubs2;
  pubs1.emplace_back(node1->create_publisher<test_msgs::msg::Empty>("topic", rclcpp::SystemDefaultsQoS()));
  pubs2.emplace_back(node2->create_publisher<test_msgs::msg::Empty>("topic", rclcpp::SystemDefaultsQoS()));

  MultiThreadedEventsExecutor executor(1);
  executor.add_node(node1);
  executor.add_node(node2);
  executor.spin();

  for (int i = 0; i < 5; i++) {
    auto msg = std::make_unique<test_msgs::msg::Empty>();
    std::cout << "Published message 1 on topic" << std::endl;
    for (auto & pub1 : pubs1) {
      pub1->publish(std::move(msg));
    }
    std::this_thread::sleep_for(50ms);
    auto msg2 = std::make_unique<test_msgs::msg::Empty>();
    std::cout << "Published message 2 on topic" << std::endl;
    for (auto & pub2 : pubs2) {
      pub2->publish(std::move(msg2));
    }
    std::this_thread::sleep_for(50ms);
  }

  std::cout << "There are " << executor.num_idle_.load() << " idle threads." << std::endl;

  auto start = std::chrono::high_resolution_clock::now();
  while (
    total_callbacks.load() < 40 &&
    (std::chrono::high_resolution_clock::now() - start < 1s))
  {
    std::this_thread::sleep_for(5ms);
  }

  executor.cancel();
  executor.remove_node(node1);

  EXPECT_EQ(total_callbacks.load(), 40);
  std::cout << "Callbacks completed: " << total_callbacks.load() << " / " << 40 << std::endl;
}

TEST_F(TestMultiThreadedEventsExecutor, multiple_nodes_pub_sub)
{
  auto node1 = std::make_shared<rclcpp::Node>("node1");
  auto node2 = std::make_shared<rclcpp::Node>("node2");

  std::atomic<int> total_callbacks{0};
  const int num_topics = 2;
  const int subs_per_topic_per_node = 2;
  const int msgs_per_pub = 1;

  std::vector<rclcpp::Publisher<test_msgs::msg::Empty>::SharedPtr> pubs1, pubs2;
  std::vector<rclcpp::Subscription<test_msgs::msg::Empty>::SharedPtr> subs1, subs2;

  for (int t = 0; t < num_topics; t++) {
    std::string topic = "topic_" + std::to_string(t);

    auto pub1 = node1->create_publisher<test_msgs::msg::Empty>(topic, 1000);
    pubs1.emplace_back(pub1);
    auto pub2 = node2->create_publisher<test_msgs::msg::Empty>(topic, 1000);
    pubs2.emplace_back(pub2);

    for (int s = 0; s < subs_per_topic_per_node; s++) {
      auto sub1 = node1->create_subscription<test_msgs::msg::Empty>(
        topic, 1000,
        [&total_callbacks, topic, s](test_msgs::msg::Empty::ConstSharedPtr msg) {
          (void)msg;
          total_callbacks.fetch_add(1);
          std::cout << "Received message in Node 1 subscription " << s << " callback for topic " << topic << ". Total callbacks: " << total_callbacks.load() << std::endl;
        });
      subs1.emplace_back(sub1);
      auto sub2 = node2->create_subscription<test_msgs::msg::Empty>(
        topic, 1000,
        [&total_callbacks, topic, s](test_msgs::msg::Empty::ConstSharedPtr msg) {
          (void)msg;
          total_callbacks.fetch_add(1);
          std::cout << "Received message in Node 2 subscription " << s << " callback for topic " << topic << ". Total callbacks: " << total_callbacks.load() << std::endl;
        });
      subs2.emplace_back(sub2);
    }
  }

  std::cout << "Subs1 size: " << subs1.size() << ", Subs2 size: " << subs2.size() << std::endl;
  std::cout << "Pubs1 size: " << pubs1.size() << ", Pubs2 size: " << pubs2.size() << std::endl;
  // 5 topics × 2 publishers/topic × 5 msgs/pub × 4 subscribers/topic = 200
  // 2 topics × 2 publishers/topic × 1 msg/pub × 4 subscribers/topic = 16
  const int expected_callbacks = num_topics * 2 * msgs_per_pub * subs_per_topic_per_node * 2;

  MultiThreadedEventsExecutor executor(10);
  executor.add_node(node1);
  executor.add_node(node2);
  executor.spin();

  std::cout << "Starting to publish messages..." << std::endl;
  std::atomic<int> num_messages_published{0};
  for (int i = 0; i < msgs_per_pub; i++) {
    for (int t = 0; t < num_topics; t++) {
      auto msg1 = std::make_unique<test_msgs::msg::Empty>();
      // std::cout << "Published message on topic " << t << std::endl;
      pubs1[t]->publish(std::move(msg1));
      num_messages_published.fetch_add(1);
      auto msg2 = std::make_unique<test_msgs::msg::Empty>();
      // std::cout << "Published message on topic " << t << std::endl;
      pubs2[t]->publish(std::move(msg2));
      num_messages_published.fetch_add(1);
    }
    std::this_thread::sleep_for(50ms);
  }

  std::cout << "Published " << num_messages_published.load() << " messages." << std::endl;

  auto start = std::chrono::steady_clock::now();
  while (
    total_callbacks.load() < expected_callbacks &&
    (std::chrono::steady_clock::now() - start < 5s))
  {
    std::this_thread::sleep_for(5ms);
  }

  executor.cancel();
  executor.remove_node(node1);
  executor.remove_node(node2);

  EXPECT_EQ(total_callbacks.load(), expected_callbacks);
  std::cout << "Callbacks completed: " << total_callbacks.load() << " / " << expected_callbacks << std::endl;
}