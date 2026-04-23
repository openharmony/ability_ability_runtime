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

#include "process_monitor.h"

#include <chrono>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace CliTool {

namespace {
constexpr int32_t ACTIVE_WAIT_MS = 50;
constexpr int32_t IDLE_WAIT_MS = 200;
}

ProcessMonitor::~ProcessMonitor()
{
    Stop();
}

void ProcessMonitor::Start()
{
    if (running_.exchange(true)) {
        return;
    }
    monitorThread_ = std::thread(&ProcessMonitor::MonitorLoop, this);
}

void ProcessMonitor::Stop()
{
    if (!running_.exchange(false)) {
        return;
    }
    if (monitorThread_.joinable()) {
        monitorThread_.join();
    }
    std::lock_guard<std::mutex> lock(entriesMutex_);
    entries_.clear();
}

void ProcessMonitor::RegisterSession(pid_t pid, const std::string &sessionId)
{
    std::lock_guard<std::mutex> lock(entriesMutex_);
    entries_[pid] = ProcessEntry {sessionId};
}

void ProcessMonitor::UnregisterSession(const std::string &sessionId)
{
    std::lock_guard<std::mutex> lock(entriesMutex_);
    for (auto it = entries_.begin(); it != entries_.end(); ++it) {
        if (it->second.sessionId == sessionId) {
            entries_.erase(it);
            return;
        }
    }
}

void ProcessMonitor::SetExitCallback(ExitCallback callback)
{
    exitCallback_ = std::move(callback);
}

void ProcessMonitor::MonitorLoop()
{
    while (running_.load(std::memory_order_acquire)) {
        std::vector<pid_t> pidsToCheck;
        {
            std::lock_guard<std::mutex> lock(entriesMutex_);
            for (const auto &[pid, entry] : entries_) {
                pidsToCheck.push_back(pid);
            }
        }

        bool handledExit = false;
        for (pid_t pid : pidsToCheck) {
            int status = 0;
            pid_t waitResult = waitpid(pid, &status, WNOHANG);
            if (waitResult == pid) {
                HandleExit(pid, status);
                handledExit = true;
            } else if (waitResult == -1 && errno == ECHILD) {
                std::lock_guard<std::mutex> lock(entriesMutex_);
                entries_.erase(pid);
            }
        }
        if (handledExit) {
            continue;
        }

        size_t activeCount = 0;
        {
            std::lock_guard<std::mutex> lock(entriesMutex_);
            activeCount = entries_.size();
        }
        int32_t sleepMs = activeCount > 0 ? ACTIVE_WAIT_MS : IDLE_WAIT_MS;
        std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
    }
}

void ProcessMonitor::HandleExit(pid_t pid, int status)
{
    ProcessEntry entry;
    {
        std::lock_guard<std::mutex> lock(entriesMutex_);
        auto it = entries_.find(pid);
        if (it == entries_.end()) {
            return;
        }
        entry = it->second;
        entries_.erase(it);
    }
    if (exitCallback_) {
        exitCallback_(entry.sessionId, status);
    }
}

} // namespace CliTool
} // namespace OHOS
