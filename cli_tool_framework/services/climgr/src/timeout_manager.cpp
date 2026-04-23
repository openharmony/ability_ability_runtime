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

#include "timeout_manager.h"

#include <unistd.h>
#include <csignal>
#include <sys/types.h>
#include <sys/wait.h>

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace CliTool {

TimeoutManager::~TimeoutManager()
{
    Stop();
}

void TimeoutManager::Start()
{
    if (running_.load()) {
        TAG_LOGW(AAFwkTag::CLI_TOOL, "TimeoutManager already running");
        return;
    }

    running_.store(true);
    timeoutThread_ = std::thread(&TimeoutManager::TimeoutCheckThread, this);

    TAG_LOGI(AAFwkTag::CLI_TOOL, "TimeoutManager started");
}

void TimeoutManager::Stop()
{
    if (!running_.load()) {
        return;
    }

    running_.store(false);

    // Wake up the waiting thread
    {
        std::lock_guard<std::mutex> lock(cvMutex_);
        cv_.notify_all();
    }

    if (timeoutThread_.joinable()) {
        timeoutThread_.join();
    }

    TAG_LOGI(AAFwkTag::CLI_TOOL, "TimeoutManager stopped");
}

void TimeoutManager::SetTimeoutCallback(TimeoutCallback callback)
{
    timeoutCallback_ = std::move(callback);
}

void TimeoutManager::SetYieldTimeoutCallback(TimeoutCallback callback)
{
    yieldTimeoutCallback_ = std::move(callback);
}

bool TimeoutManager::AddTimeoutTask(const std::string& sessionId,
                                    pid_t processId,
                                    uint32_t timeoutMs,
                                    uint32_t yieldMs)
{
    // If timeout is 0, no timeout monitoring
    if (timeoutMs == 0 && yieldMs == 0) {
        TAG_LOGI(AAFwkTag::CLI_TOOL, "No timeout for session %{public}s", sessionId.c_str());
        return false;
    }

    TimeoutTask task;
    task.sessionId = sessionId;
    task.processId = processId;
    auto now = std::chrono::steady_clock::now();
    if (timeoutMs > 0) {
        task.timeoutEnable = true;
        task.timeoutMs = timeoutMs;
        task.deadline = now + std::chrono::milliseconds(timeoutMs);
    }
    if (yieldMs > 0) {
        task.yieldEnable = true;
        task.yieldMs = yieldMs;
        task.yieldTime = now + std::chrono::milliseconds(yieldMs);
    }

    {
        std::lock_guard<std::mutex> lock(tasksMutex_);
        timeoutTasks_[sessionId] = task;
    }

    // Wake up check thread
    {
        std::lock_guard<std::mutex> lock(cvMutex_);
        cv_.notify_one();
    }

    TAG_LOGI(AAFwkTag::CLI_TOOL, "Timeout task added: %{public}s, timeout=%{public}u ms, yield=%{public}u ms",
        sessionId.c_str(), timeoutMs, yieldMs);

    return true;
}

void TimeoutManager::CancelTimeoutTask(const std::string& sessionId)
{
    std::lock_guard<std::mutex> lock(tasksMutex_);
    timeoutTasks_.erase(sessionId);

    TAG_LOGI(AAFwkTag::CLI_TOOL, "Timeout task cancelled: %{public}s", sessionId.c_str());
}

void TimeoutManager::TimeoutCheckThread()
{
    TAG_LOGI(AAFwkTag::CLI_TOOL, "Timeout check thread started");

    while (running_.load()) {
        std::vector<TimeoutTask> timedOutTasks;
        std::vector<TimeoutTask> yieldTimedOutTasks;

        {
            std::lock_guard<std::mutex> lock(tasksMutex_);

            auto now = std::chrono::steady_clock::now();

            for (auto it = timeoutTasks_.begin(); it != timeoutTasks_.end();) {
                auto& task = it->second;

                if (task.timeoutEnable && now >= task.deadline) {
                    task.timeoutEnable = false;
                    timedOutTasks.push_back(task);
                }

                if (task.yieldEnable && now >= task.yieldTime) {
                    task.yieldEnable = false;
                    yieldTimedOutTasks.push_back(task);
                }

                if (task.timeoutEnable == false && task.yieldEnable == false) {
                    it = timeoutTasks_.erase(it);
                } else {
                    ++it;
                }
            }
        }

        for (const auto& task : timedOutTasks) {
            HandleTimeout(task);
        }

        for (const auto& task : yieldTimedOutTasks) {
            HandleYieldTimeout(task);
        }

        // Wait for next check or be woken up
        std::unique_lock<std::mutex> lock(cvMutex_);
        cv_.wait_for(lock, std::chrono::milliseconds(CHECK_INTERVAL_MS));
    }

    TAG_LOGI(AAFwkTag::CLI_TOOL, "Timeout check thread exited");
}

void TimeoutManager::HandleTimeout(const struct TimeoutTask& task)
{
    // Terminate process
    if (task.processId > 0) {
        TAG_LOGI(AAFwkTag::CLI_TOOL, "Terminating timed out process: pid=%{public}d", task.processId);
        TerminateProcess(task.processId);
    }

    // Notify callback
    if (timeoutCallback_) {
        timeoutCallback_(task.sessionId);
    }
}

void TimeoutManager::HandleYieldTimeout(const struct TimeoutTask& task)
{
    // Notify callback
    if (yieldTimeoutCallback_) {
        yieldTimeoutCallback_(task.sessionId);
    }
}

void TimeoutManager::TerminateProcess(pid_t pid)
{
    if (pid > 0 && kill(pid, SIGKILL) != 0 && errno != ESRCH) {
        TAG_LOGW(AAFwkTag::CLI_TOOL, "Failed to kill process %{public}d: %{public}s",
            pid, strerror(errno));
    }
}

} // namespace CliTool
} // namespace OHOS
