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

#include "load_ability_callback_manager.h"

#include "ffrt.h"
#include "global_constant.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
LoadAbilityCallbackManager::LoadAbilityCallbackManager()
{
}

LoadAbilityCallbackManager::~LoadAbilityCallbackManager()
{}

LoadAbilityCallbackManager &LoadAbilityCallbackManager::GetInstance()
{
    static LoadAbilityCallbackManager manager;
    return manager;
}

int32_t LoadAbilityCallbackManager::AddLoadAbilityCallback(uint64_t callbackId, sptr<ILoadAbilityCallback> callback)
{
    if (callbackId == 0 || callback == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "invalid callbackId or null callback");
        return ERR_INVALID_VALUE;
    }

    std::lock_guard<ffrt::mutex> lock(callbackLock_);
    callbacks_[callbackId] = callback;

    return ERR_OK;
}

int32_t LoadAbilityCallbackManager::RemoveCallback(sptr<ILoadAbilityCallback> callback)
{
    if (callback == nullptr) {
        return ERR_INVALID_VALUE;
    }
    TAG_LOGI(AAFwkTag::APPMGR, "remove callback");
    std::lock_guard<ffrt::mutex> lock(callbackLock_);
    for (const auto &cb : callbacks_) {
        if (cb.second && cb.second->AsObject() == callback->AsObject()) {
            callbacks_.erase(cb.first);
            return ERR_OK;
        }
    }
    TAG_LOGI(AAFwkTag::APPMGR, "callback null or removed");
    return ERR_INVALID_VALUE;
}

void LoadAbilityCallbackManager::OnLoadAbilityFinished(uint64_t callbackId, int32_t pid)
{
    sptr<ILoadAbilityCallback> callback = nullptr;
    {
        std::lock_guard<ffrt::mutex> lock(callbackLock_);
        auto iter = callbacks_.find(callbackId);
        if (iter == callbacks_.end()) {
            TAG_LOGE(AAFwkTag::APPMGR, "no such callback, callbackId=%{public}s", std::to_string(callbackId).c_str());
            return;
        }
        callback = iter->second;
        callbacks_.erase(iter);
    }
    if (callback == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null callback");
        return;
    }
    callback->OnFinish(pid);
}
} // namespace AAFwk
} // namespace OHOS