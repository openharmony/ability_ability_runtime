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

#ifndef OHOS_ABILITY_RUNTIME_LOAD_ABILITY_CALLBACK_MANAGER_H
#define OHOS_ABILITY_RUNTIME_LOAD_ABILITY_CALLBACK_MANAGER_H

#include <map>
#include <mutex>
#include <unordered_map>
#include "cpp/mutex.h"

#include "iload_ability_callback.h"
#include "singleton.h"

namespace OHOS {
namespace AppExecFwk {
class LoadAbilityCallbackManager {
public:
    static LoadAbilityCallbackManager &GetInstance();

    int32_t AddLoadAbilityCallback(uint64_t callbackId, sptr<ILoadAbilityCallback> callback);

    int32_t RemoveCallback(sptr<ILoadAbilityCallback> callback);

    void OnLoadAbilityFinished(uint64_t callbackId, int32_t pid);

private:
    LoadAbilityCallbackManager();
    ~LoadAbilityCallbackManager();

    DISALLOW_COPY_AND_MOVE(LoadAbilityCallbackManager);

    ffrt::mutex callbackLock_;
    std::unordered_map<uint64_t, sptr<ILoadAbilityCallback>> callbacks_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_LOAD_ABILITY_CALLBACK_MANAGER_H