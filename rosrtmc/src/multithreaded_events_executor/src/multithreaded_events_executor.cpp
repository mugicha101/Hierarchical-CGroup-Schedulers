// Copyright 2023 iRobot Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "multithreaded_events_executor/multithreaded_events_executor.hpp"

#include <memory>
#include <utility>
#include <vector>
#include <iostream>

#include <linux/sched.h>

#include "rcpputils/scope_exit.hpp"

using namespace std::chrono_literals;

using rosrtmc::executors::MultiThreadedEventsExecutor;

MultiThreadedEventsExecutor::MultiThreadedEventsExecutor(
  const size_t num_threads,
  rclcpp::experimental::executors::EventsQueue::SharedPtr events_queue,
  bool execute_timers_separate_thread,
  const rclcpp::ExecutorOptions & options)
: rclcpp::Executor(options), num_threads_(num_threads)
{
  // Get ownership of the queue used to store events.
  if (!events_queue) {
    throw std::invalid_argument("events_queue can't be a null pointer");
  }
  events_queue_ = std::move(events_queue);

  this->num_spinning_.store(0);

  // Create timers manager
  // The timers manager can be used either to only track timers (in this case an expired
  // timer will generate an executor event and then it will be executed by the executor thread)
  // or it can also take care of executing expired timers in its dedicated thread.
  std::function<void(const rclcpp::TimerBase *,
    const std::shared_ptr<void> &)> timer_on_ready_cb = nullptr;
  if (!execute_timers_separate_thread) {
    timer_on_ready_cb =
      [this](const rclcpp::TimerBase * timer_id, const std::shared_ptr<void> & data) {
        ExecutorEvent event = {timer_id, data, -1, ExecutorEventType::TIMER_EVENT, 1};
        this->events_queue_->enqueue(event);
      };
  }
  timers_manager_ =
    std::make_shared<rclcpp::experimental::TimersManager>(context_, timer_on_ready_cb);

  this->current_entities_collection_ =
    std::make_shared<rclcpp::executors::ExecutorEntitiesCollection>();

  notify_waitable_ = std::make_shared<rclcpp::executors::ExecutorNotifyWaitable>(
    [this]() {
      // This callback is invoked when:
      // - the interrupt or shutdown guard condition is triggered:
      //    ---> we need to wake up the executor so that it can terminate
      // - a node or callback group guard condition is triggered:
      //    ---> the entities collection is changed, we need to update callbacks
      this->refresh_current_collection_from_callback_groups();
    });

  // Make sure that the notify waitable is immediately added to the collection
  // to avoid missing events
  this->add_notify_waitable_to_collection(current_entities_collection_->waitables);

  notify_waitable_->add_guard_condition(interrupt_guard_condition_);
  notify_waitable_->add_guard_condition(shutdown_guard_condition_);

  notify_waitable_->set_on_ready_callback(
    this->create_waitable_callback(notify_waitable_.get()));

  auto notify_waitable_entity_id = notify_waitable_.get();
  notify_waitable_->set_on_ready_callback(
    [this, notify_waitable_entity_id](size_t num_events, int waitable_data) {
      // The notify waitable has a special callback.
      // We don't care about how many events as when we wake up the executor we are going to
      // process everything regardless.
      // For the same reason, if an event of this type has already been pushed but it has not been
      // processed yet, we avoid pushing additional events.
      (void)num_events;
      if (notify_waitable_event_pushed_.exchange(true)) {
        return;
      }

      ExecutorEvent event =
      {notify_waitable_entity_id, nullptr, waitable_data, ExecutorEventType::WAITABLE_EVENT, 1};
      this->events_queue_->enqueue(event);
    });

  this->entities_collector_ =
    std::make_shared<rclcpp::executors::ExecutorEntitiesCollector>(notify_waitable_);
}

MultiThreadedEventsExecutor::~MultiThreadedEventsExecutor()
{
  spinning.store(false);
  timers_manager_->stop();
  notify_waitable_->clear_on_ready_callback();
  this->refresh_current_collection({});
}

void
MultiThreadedEventsExecutor::spin()
{
  timers_manager_->start();
  RCPPUTILS_SCOPE_EXIT(this->cancel(););
  spinning.exchange(true);
  for (size_t i = 0; i < num_threads_; i++) {
    spinning_threads_.emplace_back([this, i]() {this->run(i);});
  }

  while (rclcpp::ok(context_) && spinning.load()) {
    std::this_thread::sleep_for(100ms);
  }
}

void
MultiThreadedEventsExecutor::cancel()
{
  spinning.store(false);
  events_queue_->notify_all();
  timers_manager_->stop();
  for (auto & thread : spinning_threads_) {
    if (thread.joinable()) {
      thread.join();
    }
  }
  try {
    interrupt_guard_condition_->trigger();
  } catch (const rclcpp::exceptions::RCLError & ex) {
    throw std::runtime_error(
            std::string("Failed to trigger guard condition in cancel: ") + ex.what());
  }
}

void
MultiThreadedEventsExecutor::run(size_t thread_no)
{  
  struct sched_param sp = {};
  if(sched_setscheduler(0, SCHED_EXT, &sp) == -1) {
    std::cerr << "Failed to set scheduler policy: " << strerror(errno) << std::endl;
    return;
  }
  std::string name = "executor_t" + std::to_string(thread_no);
  pthread_setname_np(pthread_self(), name.c_str());
  sched_yield();
  
  this->num_spinning_++;
  RCPPUTILS_SCOPE_EXIT(this->num_spinning_--;);

  while (rclcpp::ok(context_) && spinning.load()) {
    this->num_idle_++;
    // Wait until we get an event
    ExecutorEvent event;
    bool has_event = events_queue_->dequeue(event);
    this->num_idle_--;
    if (has_event) {
      this->execute_event(event);
    }
  }
}

void
MultiThreadedEventsExecutor::add_node(
  rclcpp::node_interfaces::NodeBaseInterface::SharedPtr node_ptr, bool notify)
{
  // This field is unused because we don't have to wake up the executor when a node is added.
  (void) notify;

  // Add node to entities collector
  this->entities_collector_->add_node(node_ptr);

  this->refresh_current_collection_from_callback_groups();
}

void
MultiThreadedEventsExecutor::add_node(std::shared_ptr<rclcpp::Node> node_ptr, bool notify)
{
  this->add_node(node_ptr->get_node_base_interface(), notify);
}

void
MultiThreadedEventsExecutor::remove_node(
  rclcpp::node_interfaces::NodeBaseInterface::SharedPtr node_ptr, bool notify)
{
  // This field is unused because we don't have to wake up the executor when a node is removed.
  (void)notify;

  // Remove node from entities collector.
  // This will result in un-setting all the event callbacks from its entities.
  // After this function returns, this executor will not receive any more events associated
  // to these entities.
  this->entities_collector_->remove_node(node_ptr);

  this->refresh_current_collection_from_callback_groups();
}

void
MultiThreadedEventsExecutor::remove_node(std::shared_ptr<rclcpp::Node> node_ptr, bool notify)
{
  this->remove_node(node_ptr->get_node_base_interface(), notify);
}

void
MultiThreadedEventsExecutor::execute_event(const ExecutorEvent & event)
{
  switch (event.type) {
    case ExecutorEventType::CLIENT_EVENT:
      {
        rclcpp::ClientBase::SharedPtr client;
        {
          std::lock_guard<std::recursive_mutex> lock(collection_mutex_);
          client = this->retrieve_entity(
            static_cast<const rcl_client_t *>(event.entity_key),
            current_entities_collection_->clients);
        }
        if (client) {
          for (size_t i = 0; i < event.num_events; i++) {
            execute_client(client);
          }
        }

        break;
      }
    case ExecutorEventType::SUBSCRIPTION_EVENT:
      {
        rclcpp::SubscriptionBase::SharedPtr subscription;
        {
          std::lock_guard<std::recursive_mutex> lock(collection_mutex_);
          subscription = this->retrieve_entity(
            static_cast<const rcl_subscription_t *>(event.entity_key),
            current_entities_collection_->subscriptions);
        }
        if (subscription) {
          for (size_t i = 0; i < event.num_events; i++) {
            execute_subscription(subscription);
          }
        }
        break;
      }
    case ExecutorEventType::SERVICE_EVENT:
      {
        rclcpp::ServiceBase::SharedPtr service;
        {
          std::lock_guard<std::recursive_mutex> lock(collection_mutex_);
          service = this->retrieve_entity(
            static_cast<const rcl_service_t *>(event.entity_key),
            current_entities_collection_->services);
        }
        if (service) {
          for (size_t i = 0; i < event.num_events; i++) {
            execute_service(service);
          }
        }

        break;
      }
    case ExecutorEventType::TIMER_EVENT:
      {
        timers_manager_->execute_ready_timer(
          static_cast<const rclcpp::TimerBase *>(event.entity_key), event.data);
        break;
      }
    case ExecutorEventType::WAITABLE_EVENT:
      {
        rclcpp::Waitable::SharedPtr waitable;
        {
          std::lock_guard<std::recursive_mutex> lock(collection_mutex_);
          waitable = this->retrieve_entity(
            static_cast<const rclcpp::Waitable *>(event.entity_key),
            current_entities_collection_->waitables);
        }
        if (waitable) {
          for (size_t i = 0; i < event.num_events; i++) {
            const auto data = waitable->take_data_by_entity_id(event.waitable_data);
            waitable->execute(data);
          }
        }
        break;
      }
  }
}

void
MultiThreadedEventsExecutor::add_callback_group(
  rclcpp::CallbackGroup::SharedPtr group_ptr,
  rclcpp::node_interfaces::NodeBaseInterface::SharedPtr node_ptr,
  bool notify)
{
  // This field is unused because we don't have to wake up
  // the executor when a callback group is added.
  (void)notify;
  (void)node_ptr;

  this->entities_collector_->add_callback_group(group_ptr);

  this->refresh_current_collection_from_callback_groups();
}

void
MultiThreadedEventsExecutor::remove_callback_group(
  rclcpp::CallbackGroup::SharedPtr group_ptr, bool notify)
{
  // This field is unused because we don't have to wake up
  // the executor when a callback group is removed.
  (void)notify;

  this->entities_collector_->remove_callback_group(group_ptr);

  this->refresh_current_collection_from_callback_groups();
}

std::vector<rclcpp::CallbackGroup::WeakPtr>
MultiThreadedEventsExecutor::get_all_callback_groups()
{
  this->entities_collector_->update_collections();
  return this->entities_collector_->get_all_callback_groups();
}

std::vector<rclcpp::CallbackGroup::WeakPtr>
MultiThreadedEventsExecutor::get_manually_added_callback_groups()
{
  this->entities_collector_->update_collections();
  return this->entities_collector_->get_manually_added_callback_groups();
}

std::vector<rclcpp::CallbackGroup::WeakPtr>
MultiThreadedEventsExecutor::get_automatically_added_callback_groups_from_nodes()
{
  this->entities_collector_->update_collections();
  return this->entities_collector_->get_automatically_added_callback_groups();
}

void
MultiThreadedEventsExecutor::refresh_current_collection_from_callback_groups()
{
  // Do not rebuild if we don't need to.
  // A rebuild event could be generated, but then
  // this function could end up being called from somewhere else
  // before that event gets processed, for example if
  // a node or callback group is manually added to the executor.
  const bool notify_waitable_triggered = notify_waitable_event_pushed_.exchange(false);
  if (!notify_waitable_triggered && !this->entities_collector_->has_pending()) {
    return;
  }

  // Build the new collection
  this->entities_collector_->update_collections();
  auto callback_groups = this->entities_collector_->get_all_callback_groups();
  rclcpp::executors::ExecutorEntitiesCollection new_collection;
  rclcpp::executors::build_entities_collection(callback_groups, new_collection);

  // TODO(alsora): this may be implemented in a better way.
  // We need the notify waitable to be included in the executor "current_collection"
  // because we need to be able to retrieve events for it.
  // We could explicitly check for the notify waitable ID when we receive a waitable event
  // but I think that it's better if the waitable was in the collection and it could be
  // retrieved in the "standard" way.
  // To do it, we need to add the notify waitable as an entry in both the new and
  // current collections such that it's neither added or removed.
  this->add_notify_waitable_to_collection(new_collection.waitables);

  // Acquire lock before modifying the current collection
  std::lock_guard<std::recursive_mutex> lock(collection_mutex_);
  this->add_notify_waitable_to_collection(current_entities_collection_->waitables);

  this->refresh_current_collection(new_collection);
}

void
MultiThreadedEventsExecutor::refresh_current_collection(
  const rclcpp::executors::ExecutorEntitiesCollection & new_collection)
{
  // Acquire lock before modifying the current collection
  std::lock_guard<std::recursive_mutex> lock(collection_mutex_);

  current_entities_collection_->timers.update(
    new_collection.timers,
    [this](rclcpp::TimerBase::SharedPtr timer) {timers_manager_->add_timer(timer);},
    [this](rclcpp::TimerBase::SharedPtr timer) {timers_manager_->remove_timer(timer);});

  current_entities_collection_->subscriptions.update(
    new_collection.subscriptions,
    [this](auto subscription) {
      subscription->set_on_new_message_callback(
        this->create_entity_callback(
          subscription->get_subscription_handle().get(), ExecutorEventType::SUBSCRIPTION_EVENT));
    },
    [](auto subscription) {subscription->clear_on_new_message_callback();});

  current_entities_collection_->clients.update(
    new_collection.clients,
    [this](auto client) {
      client->set_on_new_response_callback(
        this->create_entity_callback(
          client->get_client_handle().get(), ExecutorEventType::CLIENT_EVENT));
    },
    [](auto client) {client->clear_on_new_response_callback();});

  current_entities_collection_->services.update(
    new_collection.services,
    [this](auto service) {
      service->set_on_new_request_callback(
        this->create_entity_callback(
          service->get_service_handle().get(), ExecutorEventType::SERVICE_EVENT));
    },
    [](auto service) {service->clear_on_new_request_callback();});

  // DO WE NEED THIS? WE ARE NOT DOING ANYTHING WITH GUARD CONDITIONS
  /*
  current_entities_collection_->guard_conditions.update(new_collection.guard_conditions,
    [](auto guard_condition) {(void)guard_condition;},
    [](auto guard_condition) {guard_condition->set_on_trigger_callback(nullptr);});
  */

  current_entities_collection_->waitables.update(
    new_collection.waitables,
    [this](auto waitable) {
      waitable->set_on_ready_callback(
        this->create_waitable_callback(waitable.get()));
    },
    [](auto waitable) {waitable->clear_on_ready_callback();});
}

std::function<void(size_t)>
MultiThreadedEventsExecutor::create_entity_callback(
  void * entity_key, ExecutorEventType event_type)
{
  std::function<void(size_t)>
  callback = [this, entity_key, event_type](size_t num_events) {
      ExecutorEvent event = {entity_key, nullptr, -1, event_type, num_events};
      this->events_queue_->enqueue(event);
    };
  return callback;
}

std::function<void(size_t, int)>
MultiThreadedEventsExecutor::create_waitable_callback(const rclcpp::Waitable * entity_key)
{
  std::function<void(size_t, int)>
  callback = [this, entity_key](size_t num_events, int waitable_data) {
      ExecutorEvent event =
      {entity_key, nullptr, waitable_data, ExecutorEventType::WAITABLE_EVENT, num_events};
      this->events_queue_->enqueue(event);
    };
  return callback;
}

void
MultiThreadedEventsExecutor::add_notify_waitable_to_collection(
  rclcpp::executors::ExecutorEntitiesCollection::WaitableCollection & collection)
{
  // The notify waitable is not associated to any group, so use an invalid one
  rclcpp::CallbackGroup::WeakPtr weak_group_ptr;
  collection.insert(
  {
    this->notify_waitable_.get(),
    {this->notify_waitable_, weak_group_ptr}
  });
}
