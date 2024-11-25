/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "cj_environment_callback.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
CjEnvironmentCallback::CjEnvironmentCallback()
{
}

int32_t CjEnvironmentCallback::serialNumber_ = 0;

void CjEnvironmentCallback::CallConfigurationUpdatedInner(const AppExecFwk::Configuration &config,
    const std::map<int32_t, std::function<void(CConfiguration)>> &callbacks)
{
    TAG_LOGD(AAFwkTag::APPKIT, "methodName = onConfiguration");
    for (auto &callback : callbacks) {
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, " Invalid cjCallback");
            return;
        }
        auto cfg = CreateCConfiguration(config);
        callback.second(cfg);
    }
}

void CjEnvironmentCallback::OnConfigurationUpdated(const AppExecFwk::Configuration &config)
{
    std::weak_ptr<CjEnvironmentCallback> thisWeakPtr(shared_from_this());
    std::shared_ptr<CjEnvironmentCallback> cjEnvCallback = thisWeakPtr.lock();
    if (cjEnvCallback) {
        cjEnvCallback->CallConfigurationUpdatedInner(config, onConfigurationUpdatedCallbacks_);
    }
}

void CjEnvironmentCallback::CallMemoryLevelInner(const int level,
    const std::map<int32_t, std::function<void(int32_t)>> &callbacks)
{
    TAG_LOGD(AAFwkTag::APPKIT, "onMemoryLevel");
    for (auto &callback : callbacks) {
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid jsCallback");
            return;
        }
        callback.second(static_cast<int32_t>(level));
    }
}

void CjEnvironmentCallback::OnMemoryLevel(const int level)
{
    std::weak_ptr<CjEnvironmentCallback> thisWeakPtr(shared_from_this());
    std::shared_ptr<CjEnvironmentCallback> cjEnvCallback = thisWeakPtr.lock();
    if (cjEnvCallback) {
        cjEnvCallback->CallMemoryLevelInner(level, onMemoryLevelCallbacks_);
    }
}

int32_t CjEnvironmentCallback::Register(std::function<void(CConfiguration)> cfgCallback,
    std::function<void(int32_t)> memCallback, bool isSync)
{
    int32_t callbackId = serialNumber_;
    if (serialNumber_ < INT32_MAX) {
        serialNumber_++;
    } else {
        serialNumber_ = 0;
    }
    if (isSync) {
        return -1;
    } else {
        onConfigurationUpdatedCallbacks_.emplace(callbackId, cfgCallback);
        onMemoryLevelCallbacks_.emplace(callbackId, memCallback);
    }
    return callbackId;
}

bool CjEnvironmentCallback::UnRegister(int32_t callbackId, bool isSync)
{
    TAG_LOGD(AAFwkTag::APPKIT, "callbackId : %{public}d", callbackId);
    if (isSync) {
        return false;
    }
    auto itCfg = onConfigurationUpdatedCallbacks_.find(callbackId);
    if (itCfg == onConfigurationUpdatedCallbacks_.end()) {
        TAG_LOGE(AAFwkTag::APPKIT, "callbackId: %{public}d is not in callbacks_", callbackId);
        return false;
    }
    TAG_LOGD(AAFwkTag::APPKIT, "callbacks_.callbackId : %{public}d", itCfg->first);
    auto itMem = onMemoryLevelCallbacks_.find(callbackId);
    if (itMem == onMemoryLevelCallbacks_.end()) {
        TAG_LOGE(AAFwkTag::APPKIT, "callbackId: %{public}d is not in callbacks_", callbackId);
        return false;
    }
    TAG_LOGD(AAFwkTag::APPKIT, "callbacks_.callbackId : %{public}d", itMem->first);
    return onConfigurationUpdatedCallbacks_.erase(callbackId) == 1 && onMemoryLevelCallbacks_.erase(callbackId) == 1;
}

bool CjEnvironmentCallback::IsEmpty() const
{
    return onConfigurationUpdatedCallbacks_.empty() && onMemoryLevelCallbacks_.empty();
}
}  // namespace AbilityRuntime
}  // namespace OHOS