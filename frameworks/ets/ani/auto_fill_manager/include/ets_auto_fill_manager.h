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

#ifndef OHOS_ABILITY_RUNTIME_ETS_AUTO_FILL_MANAGER_H
#define OHOS_ABILITY_RUNTIME_ETS_AUTO_FILL_MANAGER_H

#include <map>
#include <mutex>

#include "ets_auto_save_request_callback.h"

namespace OHOS {
namespace AutoFillManagerEts {
class EtsAutoFillManager : public std::enable_shared_from_this<EtsAutoFillManager> {
public:
    EtsAutoFillManager() = default;
    ~EtsAutoFillManager() = default;
    static EtsAutoFillManager &GetInstance();
    static void RequestAutoSave(ani_env *env, ani_object autoSaveCallbackObj);

private:
    void OnRequestAutoSave(ani_env *env, ani_object autoSaveCallbackObj);
    void OnRequestAutoSaveInner(ani_env *env, int32_t instanceId,
        const std::shared_ptr<EtsAutoSaveRequestCallback> &saveRequestCallback);
    std::shared_ptr<EtsAutoSaveRequestCallback> GetCallbackByInstanceId(int32_t instanceId);
    void OnRequestAutoSaveDone(int32_t instanceId);

    std::mutex mutexLock_;
    std::map<int32_t, std::weak_ptr<EtsAutoSaveRequestCallback>> saveRequestObject_;
};
void EtsAutoFillManagerInit(ani_env *env);
} // namespace AutoFillManagerEts
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_AUTO_FILL_MANAGER_H