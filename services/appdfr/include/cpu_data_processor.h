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

namespace OHOS {
namespace AppExecFwk {
struct CpuFreqData {
    uint64_t frequency;
    uint64_t runningTime;
};

struct FrequencyPair {
    uint64_t frequency;
    float percentage;
};

struct TotalTime {
    uint64_t totalRunningTime;
    uint64_t totalCpuTime;
};

struct CpuConsumeTime {
    double optimalCpuTime;
    uint64_t cpuFaultTime;
    uint64_t processCpuTime;
    uint64_t deviceRunTime;
    uint64_t cpuTime;
};

class CpuDataProcessor {
public:
    CpuDataProcessor() {};
    CpuDataProcessor(const std::vector<std::vector<CpuFreqData>> &cpuData,
        const std::vector<TotalTime> &totalTimeList, CpuConsumeTime cpuStartTime,
        int32_t pid);
    ~CpuDataProcessor() = default;

    std::vector<std::vector<CpuFreqData>> GetCpuDetailData() const;
    std::vector<TotalTime> GetTotalTimeList() const;
    CpuConsumeTime GetCpuConsumeTime() const;
    int32_t GetPid() const;

private:
    std::vector<std::vector<CpuFreqData>> handlingHalfCpuData_;
    std::vector<TotalTime> totalTimeList_;
    CpuConsumeTime cpuConsumeTime_ {};
    int32_t pid_ = 0;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_CPU_DATA_PROCESSOR_H
