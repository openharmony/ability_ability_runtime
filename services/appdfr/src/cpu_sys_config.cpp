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

#include "cpu_sys_config.h"
#include <sstream>

namespace OHOS {
namespace AppExecFwk {
namespace {
    constexpr const char* const CPU_SYS_DEVICES = "/sys/devices/system/cpu/cpu";
    constexpr const char* const CPU_TIME_IN_STATE = "/power/time_in_state";
    constexpr const char* const CPU_PROC_PREFIX = "/proc/";
    constexpr const char* const CPU_PROC_TASK = "/task/";
    constexpr const char* const CPU_PROC_STAT = "/stat";
    constexpr const char* const CPU_CAPACITY = "/cpu_capacity";
}
CpuSysConfig::CpuSysConfig()
{
}

CpuSysConfig::~CpuSysConfig()
{
}

std::string CpuSysConfig::GetFreqTimePath(int32_t cpu)
{
    std::stringstream ss;
    ss << CPU_SYS_DEVICES << cpu << CPU_TIME_IN_STATE;
    return ss.str();
}

std::string CpuSysConfig::GetMainThreadRunningTimePath(int32_t pid)
{
    std::stringstream ss;
    ss << CPU_PROC_PREFIX << pid << CPU_PROC_TASK << pid << CPU_PROC_STAT;
    return ss.str();
}

std::string CpuSysConfig::GetProcRunningTimePath(int32_t pid)
{
    std::stringstream ss;
    ss << CPU_PROC_PREFIX << pid << CPU_PROC_STAT;
    return ss.str();
}

std::string CpuSysConfig::GetMaxCoreDimpsPath(int32_t maxCpuCount)
{
    std::stringstream ss;
    ss << CPU_SYS_DEVICES << maxCpuCount << CPU_CAPACITY;
    return ss.str();
}
}  // namespace AppExecFwk
}  // namespace OHOS
