/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_EXIT_RESIDENT_PROCESS_MANAGER_H
#define OHOS_ABILITY_RUNTIME_EXIT_RESIDENT_PROCESS_MANAGER_H

#include <string>
#include <vector>

#include "app_mem_info.h"
#include "bundle_info.h"
#include "cpp/mutex.h"
#include "nocopyable.h"
#include "refbase.h"


namespace OHOS {
namespace AppExecFwk {
struct ExitResidentProcessInfo {
    ExitResidentProcessInfo() = default;
    ExitResidentProcessInfo(const std::string &bundleName, int32_t uid)
        : bundleName(bundleName), uid(uid) {}
    std::string bundleName;
    int32_t uid = 0;
};

class ExitResidentProcessManager {
public:
    static ExitResidentProcessManager &GetInstance();
    ~ExitResidentProcessManager();
    bool IsMemorySizeSufficient() const;
    bool IsNoRequireBigMemory() const;
    bool RecordExitResidentBundleName(const std::string &bundleName, int32_t uid);
    bool RecordExitResidentBundleNameOnRequireBigMemory(const std::string &bundleName, int32_t uid);
    void RecordExitResidentBundleDependedOnWeb(const std::string &bundleName, int32_t uid);
    int32_t HandleMemorySizeInSufficent();
    int32_t HandleRequireBigMemoryOptimization();
    int32_t HandleMemorySizeSufficient(std::vector<ExitResidentProcessInfo>& bundleNames);
    int32_t HandleNoRequireBigMemoryOptimization(std::vector<ExitResidentProcessInfo>& bundleNames);
    void HandleExitResidentBundleDependedOnWeb(std::vector<ExitResidentProcessInfo>& bundleNames);
    void QueryExitBundleInfos(const std::vector<ExitResidentProcessInfo>& exitBundleNames,
        std::vector<AppExecFwk::BundleInfo>& exitBundleInfos);
    bool IsKilledForUpgradeWeb(const std::string &bundleName) const;

private:
    ExitResidentProcessManager();
    MemoryState currentMemorySizeState_ = MemoryState::MEMORY_RECOVERY;
    MemoryState currentBigMemoryState_ = MemoryState::NO_REQUIRE_BIG_MEMORY;
    std::vector<ExitResidentProcessInfo> exitResidentInfos_;
    std::vector<ExitResidentProcessInfo> exitResidentBigMemoryInfos_;
    std::vector<ExitResidentProcessInfo> exitResidentBundlesDependedOnWeb_;
    mutable ffrt::mutex mutexLock_;
    mutable ffrt::mutex webMutexLock_;
    mutable ffrt::mutex mutexLockBigMemory_;
    DISALLOW_COPY_AND_MOVE(ExitResidentProcessManager);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_EXIT_RESIDENT_PROCESS_MANAGER_H
