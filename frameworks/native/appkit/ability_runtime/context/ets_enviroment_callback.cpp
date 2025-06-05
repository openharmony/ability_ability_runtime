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

#include "ets_enviroment_callback.h"

#include "ani_common_configuration.h"
#include "hilog_tag_wrapper.h"
#include "ani_enum_convert.h"
#include "app_mem_info.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char* APPLICATION_ENVIROMENT_CALLBACK =
    "L@ohos/app/ability/EnvironmentCallback/EnvironmentCallbackInner;";
constexpr const char* APPLICATION_MEMORYLEVEL =
    "L@ohos/app/ability/AbilityConstant/AbilityConstant/MemoryLevel;";
constexpr const char* APPLICATION_CONFIGURATION =
    "L@ohos/app/ability/AbilityConstant/AbilityConstant/MemoryLevel;";
}
EtsEnviromentCallback::EtsEnviromentCallback(ani_env *env)
    : ani_env_(env) {}

int32_t EtsEnviromentCallback::Register(ani_object aniCallback)
{
    if (ani_env_ == nullptr) {
        return -1;
    }
    int32_t callbackId = serialNumber_;
    if (serialNumber_ < INT32_MAX) {
        serialNumber_++;
    } else {
        serialNumber_ = 0;
    }
    ani_ref aniCallbackRef = nullptr;
    ani_env_->GlobalReference_Create(aniCallback, &aniCallbackRef);

    std::lock_guard lock(Mutex_);
    enviromentAniCallbacks_.emplace(callbackId, aniCallbackRef);
    return callbackId;
}

bool EtsEnviromentCallback::UnRegister(int32_t callbackId)
{
    std::lock_guard lock(Mutex_);
    auto it = enviromentAniCallbacks_.find(callbackId);
    if (it == enviromentAniCallbacks_.end()) {
        TAG_LOGE(AAFwkTag::APPKIT, "callbackId: %{public}d not in callbacks_", callbackId);
        return false;
    }
    TAG_LOGD(AAFwkTag::APPKIT, "callbacks_.callbackId: %{public}d", it->first);
    return enviromentAniCallbacks_.erase(callbackId) == 1;
}

void EtsEnviromentCallback::OnMemoryLevel(const int level)
{
    TAG_LOGD(AAFwkTag::APPKIT, "OnMemoryLevel Call");
    if (ani_env_ == nullptr || enviromentAniCallbacks_.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "null aniEnv");
        return;
    }
    ani_class cls {};
    ani_status status = ani_env_->FindClass(APPLICATION_ENVIROMENT_CALLBACK, &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "FindClass status: %{public}d", status);
        return;
    }
    ani_method method {};
    if ((status = ani_env_->Class_FindMethod(cls, "onMemoryLevel", APPLICATION_MEMORYLEVEL, &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_FindMethod status: %{public}d", status);
        return;
    }
    ani_enum_item memoryLevel {};
    OHOS::AAFwk::AniEnumConvertUtil::EnumConvertNativeToSts(ani_env_,
        APPLICATION_MEMORYLEVEL, (AppExecFwk::MemoryLevel)level, memoryLevel);
    if (memoryLevel == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "create memoryLevel failed");
        return;
    }
    // ani_object memoryLevelObj = reinterpret_cast<ani_object>(memoryLevel);
    // if (memoryLevelObj == nullptr) {
    //     TAG_LOGE(AAFwkTag::APPKIT, "create memoryLevelObj failed");
    //     return;
    // }
    std::lock_guard lock(Mutex_);
    for (auto &callback : enviromentAniCallbacks_) {
        ani_status status = ANI_ERROR;
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, "callback object is null");
            return;
        }
        ani_object envCallback = reinterpret_cast<ani_object>(callback.second);
        if ((status = ani_env_->Object_CallMethod_Void(envCallback, method, memoryLevel)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::APPKIT, "Object_CallMethod_Void status: %{public}d", status);
        }
    }
}

void EtsEnviromentCallback::OnConfigurationUpdated(const AppExecFwk::Configuration &config)
{
    TAG_LOGD(AAFwkTag::APPKIT, "OnConfigurationUpdated Call");
    if (ani_env_ == nullptr || enviromentAniCallbacks_.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "null aniEnv");
        return;
    }
    ani_class cls {};
    ani_status status = ani_env_->FindClass(APPLICATION_ENVIROMENT_CALLBACK, &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "FindClass status: %{public}d", status);
        return;
    }
    ani_method method {};
    if ((status = ani_env_->Class_FindMethod(cls, "onConfigurationUpdated",
        APPLICATION_CONFIGURATION, &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_FindMethod status: %{public}d", status);
        return;
    }
    ani_object configObj = OHOS::AppExecFwk::WrapConfiguration(ani_env_, config);
    if (configObj == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "create configObj failed");
        return;
    }
    std::lock_guard lock(Mutex_);
    for (auto &callback : enviromentAniCallbacks_) {
        ani_status status = ANI_ERROR;
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, "callback object is null");
            return;
        }
        ani_object envCallback = reinterpret_cast<ani_object>(callback.second);
        if ((status = ani_env_->Object_CallMethod_Void(envCallback, method, configObj)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::APPKIT, "Object_CallMethod_Void status: %{public}d", status);
        }
    }
}
} // namespace AbilityRuntime
} // namespace OHOS