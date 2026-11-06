#include "MeshMessengerCallbackThread.h"
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>

int main() {
  const auto caller = std::this_thread::get_id();
  uint64_t output = 0;
  const int32_t failed = MeshMessengerRunCallbackOnNativeStack([&] {
    assert(std::this_thread::get_id() != caller);
    output = UINT64_MAX;
    return int32_t{5};
  });
  assert(failed == 5 && output == UINT64_MAX);
  std::atomic<int> running{0}, maximum{0};
  std::vector<std::thread> callers;
  std::atomic<int> completed{0};
  for (int index = 0; index < 16; ++index) {
    callers.emplace_back([&, index] {
      uint64_t private_output = 0;
      auto result = MeshMessengerRunCallbackOnNativeStack([&] {
        const int count = ++running;
        int previous = maximum.load();
        while (count > previous && !maximum.compare_exchange_weak(previous, count)) {}
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        private_output = uint64_t{1} << index;
        --running;
        return int32_t{index + 1};
      });
      assert(result == index + 1 && private_output == (uint64_t{1} << index));
      ++completed;
    });
  }
  for (auto &thread : callers) thread.join();
  assert(completed == 16 && maximum == 1 && running == 0);
}
