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
    "@ohos.app.ability.EnvironmentCallback.EnvironmentCallbackInner";
constexpr const char* APPLICATION_MEMORYLEVEL =
    "C{@ohos.app.ability.AbilityConstant.AbilityConstant.MemoryLevel}:";
constexpr const char* APPLICATION_MEMORYLEVEL_ENUM =
    "@ohos.app.ability.AbilityConstant.AbilityConstant.MemoryLevel";
constexpr const char* APPLICATION_CONFIGURATION =
    "C{@ohos.app.ability.Configuration.Configuration}:";
}
EtsEnviromentCallback::EtsEnviromentCallback(ani_vm *etsVm) : etsVm_(etsVm) {}

EtsEnviromentCallback::~EtsEnviromentCallback()
{
    bool isAttachThread = false;
    ani_env *env = AppExecFwk::AttachAniEnv(etsVm_, isAttachThread);
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "GetEnv failed");
        return;
    }
    ani_status status = ANI_ERROR;
    {
        std::lock_guard lock(mutex_);
        for (auto it = enviromentAniCallbacks_.begin(); it != enviromentAniCallbacks_.end();) {
            if ((status = env->GlobalReference_Delete(it->second)) != ANI_OK) {
                TAG_LOGE(AAFwkTag::APPKIT, "GlobalReference_Delete status: %{public}d", status);
            }
            it++;
        }
    }
    AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
};

int32_t EtsEnviromentCallback::Register(ani_object aniCallback)
{
    int32_t callbackId = serialNumber_;
    if (serialNumber_ < INT32_MAX) {
        serialNumber_++;
    } else {
        serialNumber_ = 0;
    }
    ani_ref aniCallbackRef = nullptr;
    bool isAttachThread = false;
    ani_env *env = AppExecFwk::AttachAniEnv(etsVm_, isAttachThread);
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "GetEnv failed");
        return -1;
    }
    ani_status status = ANI_ERROR;
    if ((status = env->GlobalReference_Create(aniCallback, &aniCallbackRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "GlobalReference_Create status: %{public}d", status);
        AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
        return -1;
    }
    {
        std::lock_guard lock(mutex_);
        enviromentAniCallbacks_.emplace(callbackId, aniCallbackRef);
    }
    AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
    return callbackId;
}

bool EtsEnviromentCallback::UnRegister(int32_t callbackId)
{
    std::lock_guard lock(mutex_);
    auto it = enviromentAniCallbacks_.find(callbackId);
    if (it == enviromentAniCallbacks_.end()) {
        TAG_LOGE(AAFwkTag::APPKIT, "callbackId: %{public}d not in callbacks_", callbackId);
        return false;
    }
    bool isAttachThread = false;
    ani_env *env = AppExecFwk::AttachAniEnv(etsVm_, isAttachThread);
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "GetEnv failed");
        return false;
    }
    TAG_LOGD(AAFwkTag::APPKIT, "callbacks_.callbackId: %{public}d", it->first);
    ani_status status = ANI_ERROR;
    if ((status = env->GlobalReference_Delete(it->second)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "GlobalReference_Delete status: %{public}d", status);
        AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
        return false;
    }
    AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
    return enviromentAniCallbacks_.erase(callbackId) == 1;
}

void EtsEnviromentCallback::OnMemoryLevel(const int level)
{
    TAG_LOGD(AAFwkTag::APPKIT, "OnMemoryLevel Call");
    if (enviromentAniCallbacks_.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "null enviromentAniCallbacks_");
        return;
    }
    bool isAttachThread = false;
    ani_env *env = AppExecFwk::AttachAniEnv(etsVm_, isAttachThread);
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "GetEnv failed");
        return;
    }
    ani_class cls {};
    ani_status status = env->FindClass(APPLICATION_ENVIROMENT_CALLBACK, &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "FindClass status: %{public}d", status);
        AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
        return;
    }
    ani_method method {};
    if ((status = env->Class_FindMethod(cls, "onMemoryLevel", APPLICATION_MEMORYLEVEL, &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_FindMethod status: %{public}d", status);
        AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
        return;
    }
    ani_enum_item memoryLevel {};
    OHOS::AAFwk::AniEnumConvertUtil::EnumConvert_NativeToEts(env,
        APPLICATION_MEMORYLEVEL_ENUM, (AppExecFwk::MemoryLevel)level, memoryLevel);
    if (memoryLevel == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "create memoryLevel failed");
        AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
        return;
    }
    {
        std::lock_guard lock(mutex_);
        for (auto &callback : enviromentAniCallbacks_) {
            ani_status status = ANI_ERROR;
            if (!callback.second) {
                TAG_LOGE(AAFwkTag::APPKIT, "callback object is null");
                AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
                return;
            }
            ani_object envCallback = reinterpret_cast<ani_object>(callback.second);
            if ((status = env->Object_CallMethod_Void(envCallback, method, memoryLevel)) != ANI_OK) {
                TAG_LOGE(AAFwkTag::APPKIT, "Object_CallMethod_Void status: %{public}d", status);
            }
        }
    }
    AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
}

void EtsEnviromentCallback::OnConfigurationUpdated(const AppExecFwk::Configuration &config)
{
    TAG_LOGD(AAFwkTag::APPKIT, "OnConfigurationUpdated Call");
    if (enviromentAniCallbacks_.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "null enviromentAniCallbacks_");
        return;
    }
    bool isAttachThread = false;
    ani_env *env = AppExecFwk::AttachAniEnv(etsVm_, isAttachThread);
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "GetEnv failed");
        return;
    }
    ani_class cls {};
    ani_status status = env->FindClass(APPLICATION_ENVIROMENT_CALLBACK, &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "FindClass status: %{public}d", status);
        AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
        return;
    }
    ani_method method {};
    if ((status = env->Class_FindMethod(cls, "onConfigurationUpdated",
        APPLICATION_CONFIGURATION, &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_FindMethod status: %{public}d", status);
        AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
        return;
    }
    ani_object configObj = OHOS::AppExecFwk::WrapConfiguration(env, config);
    if (configObj == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "create configObj failed");
        AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
        return;
    }
    {
        std::lock_guard lock(mutex_);
        for (auto &callback : enviromentAniCallbacks_) {
            ani_status status = ANI_ERROR;
            if (!callback.second) {
                TAG_LOGE(AAFwkTag::APPKIT, "callback object is null");
                AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
                return;
            }
            ani_object envCallback = reinterpret_cast<ani_object>(callback.second);
            if ((status = env->Object_CallMethod_Void(envCallback, method, configObj)) != ANI_OK) {
                TAG_LOGE(AAFwkTag::APPKIT, "Object_CallMethod_Void status: %{public}d", status);
            }
        }
    }
    AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
}
} // namespace AbilityRuntime
} // namespace OHOS