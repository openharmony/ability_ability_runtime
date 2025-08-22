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
#include "cpu_data_processor.h"

namespace OHOS {
namespace AppExecFwk {
CpuDataProcessor::CpuDataProcessor(const std::vector<std::vector<CpuFreqData>> &cpuData,
    const std::vector<TotalTime> &totalTimeList, CpuStartTime cpuStartTime,
    const std::string &stackPath, int32_t pid)
    : handlingHalfCpuData_(cpuData), totalTimeList_(totalTimeList), cpuStartTime_(cpuStartTime), stackPath_(stackPath),
    pid_(pid)
{
}

std::vector<std::vector<CpuFreqData>> CpuDataProcessor::GetHandlingHalfCpuData() const
{
    return handlingHalfCpuData_;
}

std::vector<TotalTime> CpuDataProcessor::GetTotalTimeList() const
{
    return totalTimeList_;
}

CpuStartTime CpuDataProcessor::GetCpuStartTime() const
{
    return cpuStartTime_;
}

std::string CpuDataProcessor::GetStackPath() const
{
    return stackPath_;
}

int32_t CpuDataProcessor::GetPid() const
{
    return pid_;
}
}  // namespace AppExecFwk
}  // namespace OHOS
