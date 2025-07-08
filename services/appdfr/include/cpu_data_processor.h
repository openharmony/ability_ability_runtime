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
#ifndef OHOS_ABILITY_RUNTIME_CPU_DATA_PROCESSOR_H
#define OHOS_ABILITY_RUNTIME_CPU_DATA_PROCESSOR_H

#include <vector>
#include <string>

#include "appfreeze_data.h"

namespace OHOS {
namespace AppExecFwk {
class CpuDataProcessor {
public:
    CpuDataProcessor() {};
    CpuDataProcessor(const std::vector<std::vector<CpuFreqData>> &cpuData,
        const std::vector<TotalTime> &totalTimeList, CpuStartTime cpuStartTime,
        const std::string &stackPath, int32_t pid);
    ~CpuDataProcessor() = default;

    std::vector<std::vector<CpuFreqData>> GetHandlingHalfCpuData() const;
    std::vector<TotalTime> GetTotalTimeList() const;
    CpuStartTime GetCpuStartTime() const;
    std::string GetStackPath() const;
    int32_t GetPid() const;

private:
    std::vector<std::vector<CpuFreqData>> handlingHalfCpuData_;
    std::vector<TotalTime> totalTimeList_;
    CpuStartTime cpuStartTime_ {};
    std::string stackPath_;
    int32_t pid_ = 0;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_CPU_DATA_PROCESSOR_H
