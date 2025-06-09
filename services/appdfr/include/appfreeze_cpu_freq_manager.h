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
#ifndef OHOS_ABILITY_RUNTIME_APPFREEZE_CPU_FREQ_MANAGER_H
#define OHOS_ABILITY_RUNTIME_APPFREEZE_CPU_FREQ_MANAGER_H

#include <vector>
#include <mutex>

#include "singleton.h"
#include "appfreeze_data.h"
#include "ffrt.h"

namespace OHOS {
namespace AppExecFwk {
class AppfreezeCpuFreqManager : public DelayedSingleton<AppfreezeCpuFreqManager>,
    public std::enable_shared_from_this<AppfreezeCpuFreqManager> {
        DISALLOW_COPY_AND_MOVE(AppfreezeCpuFreqManager);
public:
    AppfreezeCpuFreqManager();
    ~AppfreezeCpuFreqManager();
    
    static std::shared_ptr<AppfreezeCpuFreqManager> GetInstance();
    void SetHalfStackPath(const std::string& stackpath);
    void InitHalfCpuInfo(int32_t pid);
    std::string WriteCpuInfoToFile(const std::string &bundleName, int32_t uid, int32_t pid,
        const std::string &eventName);

private:
    bool ReadCpuDataByNum(int32_t num, std::vector<CpuFreqData>& parseDatas, TotalTime& totalTime);
    void ParseCpuData(std::vector<std::vector<CpuFreqData>>& datas, std::vector<TotalTime>& totalTimeLists);
    std::string GetCpuStr(int code, std::vector<FrequencyPair>& freqPairs, float percentage);
    bool GetCpuTotalValue(size_t i, std::vector<TotalTime> totalTimeList,
        std::vector<TotalTime> blockTotalTimeList, TotalTime& totalTime);
    uint64_t GetProcessCpuTime(int32_t pid);
    uint64_t GetDeviceRuntime();
    std::string GetCpuInfoContent();
    std::string GetStartTime(uint64_t start);
    uint64_t GetAppCpuTime(int32_t pid);
    double GetOptimalCpuTime(int32_t pid);
    std::string GetStaticInfoHead();
    std::string GetStaticInfo(int32_t pid);
    void WriteDfxLogToFile(const std::string& filePath, const std::string& bundleName);
    void Clear();

    static ffrt::mutex singletonMutex_;
    static std::shared_ptr<AppfreezeCpuFreqManager> instance_;
    static ffrt::mutex freezeInfoMutex_;
    static std::vector<std::vector<CpuFreqData>> handlingHalfCpuData_;
    static std::vector<TotalTime> totalTimeList_;
    static uint64_t halfTime_;
    static uint64_t optimalCpuTime_;
    static std::string stackPath_;
    static int cpuCount_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_APPFREEZE_CPU_FREQ_MANAGER_H
