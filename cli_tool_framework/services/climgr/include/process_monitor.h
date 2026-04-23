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

#ifndef OHOS_ABILITY_RUNTIME_PROCESS_MONITOR_H
#define OHOS_ABILITY_RUNTIME_PROCESS_MONITOR_H

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <sys/types.h>

namespace OHOS {
namespace CliTool {

class ProcessMonitor {
public:
    using ExitCallback = std::function<void(const std::string &, int)>;

    ProcessMonitor() = default;
    ~ProcessMonitor();

    void Start();
    void Stop();

    void RegisterSession(pid_t pid, const std::string &sessionId);
    void UnregisterSession(const std::string &sessionId);

    void SetExitCallback(ExitCallback callback);

private:
    struct ProcessEntry {
        std::string sessionId;
    };

    void MonitorLoop();
    void HandleExit(pid_t pid, int status);

    std::atomic<bool> running_ {false};
    std::thread monitorThread_;
    std::mutex entriesMutex_;
    std::unordered_map<pid_t, ProcessEntry> entries_;
    ExitCallback exitCallback_;
};

} // namespace CliTool
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_PROCESS_MONITOR_H
