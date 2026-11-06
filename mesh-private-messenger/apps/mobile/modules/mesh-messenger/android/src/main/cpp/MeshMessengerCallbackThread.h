#pragma once

#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <pthread.h>

inline std::mutex &MeshMessengerCallbackThreadLock() {
  static std::mutex lock;
  return lock;
}

// ART derives its stack bounds during attachment. A Mesh actor uses an alternate
// coroutine stack, so both attachment and Java calls must use a normal OS stack.
// At most one worker exists; input/output borrows remain live until it completes.
template <typename Callback>
int32_t MeshMessengerRunCallbackOnNativeStack(Callback &&callback) {
  std::lock_guard<std::mutex> serial(MeshMessengerCallbackThreadLock());
  struct Work {
    Callback &callback;
    std::mutex lock;
    std::condition_variable changed;
    bool finished = false;
    int32_t result = 3;
    explicit Work(Callback &value) : callback(value) {}
  } work(callback);
  pthread_t thread;
  const auto run = [](void *context) -> void * {
    auto &job = *static_cast<Work *>(context);
    const int32_t result = job.callback();
    {
      std::lock_guard<std::mutex> guard(job.lock);
      job.result = result;
      job.finished = true;
      job.changed.notify_one();
    }
    return nullptr;
  };
  if (pthread_create(&thread, nullptr, run, &work) != 0) return 3;
  {
    std::unique_lock<std::mutex> guard(work.lock);
    work.changed.wait(guard, [&] { return work.finished; });
  }
  // Completion above fences all accesses to borrowed buffers even if joining
  // unexpectedly fails. No detached worker can retain the caller's arguments.
  return pthread_join(thread, nullptr) == 0 ? work.result : 3;
}
