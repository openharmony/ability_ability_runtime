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

#ifndef OHOS_ABILITY_RUNTIME_KILLING_PROCESS_MANAGER_H
#define OHOS_ABILITY_RUNTIME_KILLING_PROCESS_MANAGER_H

#include <string>
#include <unordered_set>

#include "cpp/mutex.h"
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {
class KillingProcessManager {
public:
    static KillingProcessManager& GetInstance();
    ~KillingProcessManager() = default;
    bool IsCallerKilling(std::string callerKey) const;
    void AddKillingCallerKey(std::string callerKey);
    void RemoveKillingCallerKey(std::string callerKey);

private:
    KillingProcessManager() = default;
    mutable ffrt::mutex mutex_;
    std::unordered_set<std::string> killingCallerKeySet_;
    DISALLOW_COPY_AND_MOVE(KillingProcessManager);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_KILLING_PROCESS_MANAGER_H
