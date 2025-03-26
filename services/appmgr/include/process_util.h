/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_APPEXECFWK_PROCESS_UTIL_H
#define OHOS_ABILITY_RUNTIME_APPEXECFWK_PROCESS_UTIL_H

#include <list>
#include <sys/stat.h>

#include "file_ex.h"
#include "hilog_tag_wrapper.h"
#include "securec.h"
#include "simple_process_info.h"

namespace OHOS {
namespace AppExecFwk {
namespace ProcessUtil {

static bool ProcessExist(pid_t pid)
{
    char pidPath[128] = {0};
    struct stat statBuf;
    if (!pid) {
        return false;
    }
    if (snprintf_s(pidPath, sizeof(pidPath), sizeof(pidPath) - 1, "/proc/%d/status", pid) < 0) {
        return false;
    }
    if (stat(pidPath, &statBuf) == 0) {
        return true;
    }
    return false;
}

static bool ReadProcessName(pid_t pid, std::string &pidProcessName)
{
    pidProcessName.clear();
    char pidPath[128] = {0};
    if (snprintf_s(pidPath, sizeof(pidPath), sizeof(pidPath) - 1, "/proc/%d/cmdline", pid) < 0) {
        return false;
    }
    std::string processPath = pidPath;
    std::string name;
    OHOS::LoadStringFromFile(processPath, name);
    if (name.empty()) {
        return false;
    }
    for (char c : name) {
        if (c == '\0') {
            break;
        }
        pidProcessName += c;
    }
    return true;
}

static bool ProcessExist(pid_t pid, const std::string &processName)
{
    if (!ProcessExist(pid)) {
        return false;
    }
    std::string pidProcessName;
    ReadProcessName(pid, pidProcessName);
    if (pidProcessName.empty()) {
        return true;
    }
    return pidProcessName == processName;
}

static bool CheckAllProcessExit(std::list<SimpleProcessInfo> &processInfos)
{
    // use pid and process name to check if process exists
    for (auto iter = processInfos.begin(); iter != processInfos.end();) {
        if (!ProcessExist((*iter).pid, (*iter).processName)) {
            iter = processInfos.erase(iter);
        } else {
            iter++;
        }
    }
    return processInfos.empty();
}

static bool CheckAllProcessExit(std::list<pid_t> &pids)
{
    for (auto iter = pids.begin(); iter != pids.end();) {
        if (!ProcessExist(*iter)) {
            iter = pids.erase(iter);
        } else {
            iter++;
        }
    }
    return pids.empty();
}

static bool IsAllProcessKilled(std::list<SimpleProcessInfo> &processInfos)
{
    bool processExists = false;
    for (auto &item : processInfos) {
        if (ProcessExist(item.pid, item.processName)) {
            TAG_LOGI(AAFwkTag::APPMGR, "process not exit %{public}d, %{public}s",
                static_cast<int32_t>(item.pid), item.processName.c_str());
            return false;
        }
    }
    return true;
}

static void UpdateProcessNameByProcFile(std::list<SimpleProcessInfo> &processInfos)
{
    TAG_LOGI(AAFwkTag::APPMGR, "UpdateProcessNameByProcFile");
    for (auto &item : processInfos) {
        std::string processName = item.processName;
        ReadProcessName(item.pid, item.processName);
        if (item.processName.empty()) {
            TAG_LOGI(AAFwkTag::APPMGR, "%{public}s proc empty", processName.c_str());
        }
    }
}
}  // namespace ProcessUtil
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // OHOS_ABILITY_RUNTIME_APPEXECFWK_PROCESS_UTIL_H