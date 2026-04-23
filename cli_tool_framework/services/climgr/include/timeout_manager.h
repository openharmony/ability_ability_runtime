/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_ABILITY_RUNTIME_TIMEOUT_MANAGER_H
#define OHOS_ABILITY_RUNTIME_TIMEOUT_MANAGER_H

#include <string>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <atomic>
#include <condition_variable>
#include <chrono>
#include <memory>
#include <functional>

namespace OHOS {
namespace CliTool {

/**
 * @brief Timeout callback function type
 * @param sessionId Session ID that timed out
 */
using TimeoutCallback = std::function<void(const std::string&)>;

/**
 * @brief Timeout manager for CLI tool execution
 *
 * Monitors task execution time and terminates process on timeout.
 * Supports both synchronous and asynchronous execution modes.
 */
class TimeoutManager {
public:
    TimeoutManager() = default;
    ~TimeoutManager();

    /**
     * @brief Start the timeout manager background thread
     */
    void Start();

    /**
     * @brief Stop the timeout manager and cleanup resources
     */
    void Stop();

    /**
     * @brief Set timeout callback
     * @param callback Function to call when timeout occurs
     */
    void SetTimeoutCallback(TimeoutCallback callback);

    void SetYieldTimeoutCallback(TimeoutCallback callback);

    bool AddTimeoutTask(const std::string& sessionId,
                        pid_t processId,
                        uint32_t timeoutMs,
                        uint32_t yieldMs);

    /**
     * @brief Cancel timeout monitoring for a task
     * @param sessionId Session ID
     */
    void CancelTimeoutTask(const std::string& sessionId);

private:
    struct TimeoutTask {
        std::string sessionId;
        pid_t processId;
        bool timeoutEnable = false;
        bool yieldEnable = false;
        uint32_t timeoutMs;
        uint32_t yieldMs;
        std::chrono::time_point<std::chrono::steady_clock> deadline;
        std::chrono::time_point<std::chrono::steady_clock> yieldTime;
    };

    /**
     * @brief Background thread for timeout checking
     */
    void TimeoutCheckThread();

    /**
     * @brief Handle timeout for a specific task
     * @param task Timeout task
     */
    void HandleTimeout(const TimeoutTask& task);

    void HandleYieldTimeout(const TimeoutTask& task);

    /**
     * @brief Terminate process with SIGKILL
     * @param pid Process ID
     */
    void TerminateProcess(pid_t pid);

private:
    std::unordered_map<std::string, TimeoutTask> timeoutTasks_;
    std::mutex tasksMutex_;

    std::atomic<bool> running_{false};
    std::thread timeoutThread_;
    std::condition_variable cv_;
    std::mutex cvMutex_;

    TimeoutCallback timeoutCallback_;
    TimeoutCallback yieldTimeoutCallback_;

    static constexpr uint32_t CHECK_INTERVAL_MS = 100;      // 100ms check interval
};

} // namespace CliTool
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_TIMEOUT_MANAGER_H
