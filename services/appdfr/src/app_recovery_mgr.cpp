/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#include "app_recovery_mgr.h"
#include "hilog_tag_wrapper.h"
 
namespace OHOS {
namespace AppRecoveryMgr {
 
AppRecoveryMgr::AppRecoveryMgr()
{
}
 
AppRecoveryMgr::~AppRecoveryMgr()
{
}
 
AppRecoveryMgr& AppRecoveryMgr::GetInstance()
{
    static AppRecoveryMgr instance;
    return instance;
}
 
void AppRecoveryMgr::Init(const std::shared_ptr<AppExecFwk::EventHandler>& handler)
{
    std::lock_guard<std::mutex> lock(mutex_);
    handler_ = handler;
    TAG_LOGI(AAFwkTag::APPDFR, "AppRecoveryMgr initialized");
}
 
void AppRecoveryMgr::SetOnRemoteDieCallback(const sptr<IRemoteObject>& abilityToken,
    const std::function<void(const sptr<IRemoteObject>&)>& callback)
{
    if (abilityToken == nullptr || callback == nullptr) {
        TAG_LOGI(AAFwkTag::APPDFR, "SetOnRemoteDieCallback: invalid parameter");
        return;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = dieCallbacks_.find(abilityToken);
    if (it != dieCallbacks_.end()) {
        TAG_LOGI(AAFwkTag::APPDFR, "SetOnRemoteDieCallback: callback already exists, updating");
        dieCallbacks_.erase(it);
    }
    
    dieCallbacks_.emplace(abilityToken, callback);
    TAG_LOGI(AAFwkTag::APPDFR, "SetOnRemoteDieCallback: callback set for ability token");
}
 
void AppRecoveryMgr::RemoveOnRemoteDieCallback(const sptr<IRemoteObject>& abilityToken)
{
    if (abilityToken == nullptr) {
        TAG_LOGI(AAFwkTag::APPDFR, "RemoveOnRemoteDieCallback: invalid parameter");
        return;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = dieCallbacks_.find(abilityToken);
    if (it != dieCallbacks_.end()) {
        dieCallbacks_.erase(it);
        TAG_LOGI(AAFwkTag::APPDFR, "RemoveOnRemoteDieCallback: callback removed");
    }
}
 
std::function<void(const sptr<IRemoteObject>&)> AppRecoveryMgr::FindCallback(const sptr<IRemoteObject>& remote)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (remote == nullptr) {
        return nullptr;
    }
    
    auto it = dieCallbacks_.find(remote);
    if (it != dieCallbacks_.end()) {
        return it->second;
    }
    
    return nullptr;
}
 
void AppRecoveryMgr::HandleAppDied(const sptr<IRemoteObject>& remote)
{
    TAG_LOGI(AAFwkTag::APPDFR, "HandleAppDied: app died event received");
    
    auto callback = FindCallback(remote);
    if (callback == nullptr) {
        TAG_LOGI(AAFwkTag::APPDFR, "HandleAppDied: no callback found for this remote");
        return;
    }
    
    if (handler_ != nullptr) {
        auto task = [callback, remote]() {
            callback(remote);
        };
        handler_->PostTask(task);
        TAG_LOGI(AAFwkTag::APPDFR, "HandleAppDied: callback posted to handler");
    } else {
        callback(remote);
        TAG_LOGI(AAFwkTag::APPDFR, "HandleAppDied: callback executed directly no handler");
    }
}
 
void AppRecoveryMgr::Clear()
{
    std::lock_guard<std::mutex> lock(mutex_);
    dieCallbacks_.clear();
    handler_ = nullptr;
    TAG_LOGI(AAFwkTag::APPDFR, "AppRecoveryMgr cleared");
}
 
} // namespace AppRecoveryMgr
} // namespace OHOS