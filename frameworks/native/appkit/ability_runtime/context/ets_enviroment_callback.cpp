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

namespace OHOS {
namespace AbilityRuntime {
EtsEnviromentCallback::EtsEnviromentCallback(ani_env *env)
    : ani_env_(env) {}

int32_t EtsEnviromentCallback::serialNumber_ = 0;

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

    enviromentAniCallbacks_.emplace(callbackId, aniCallbackRef);
    return callbackId;
}

void EtsEnviromentCallback::OnMemoryLevel(const int level)
{
    return;
}

void EtsEnviromentCallback::OnConfigurationUpdated(const AppExecFwk::Configuration &config)
{
    if (ani_env_ == nullptr || enviromentAniCallbacks_.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "null aniEnv");
        return;
    }

    for (auto &callback : enviromentAniCallbacks_) {
        ani_status status = ANI_ERROR;
        if (!callback.second) {
            return;
        }
        ani_object envCallback = reinterpret_cast<ani_object>(callback.second);
        ani_ref OnConfigurationUpdatedRef {};

        if ((status = ani_env_->Object_GetFieldByName_Ref(envCallback,
            "onConfigurationUpdated", &OnConfigurationUpdatedRef)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::APPKIT, "get onConfigurationUpdated failed, status: %{public}d", status);
            return;
        }
        ani_fn_object OnConfigurationUpdatedFunc = reinterpret_cast<ani_fn_object>(OnConfigurationUpdatedRef);

        ani_object configObj = OHOS::AppExecFwk::WrapConfiguration(ani_env_, config);
        if (configObj == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "create configObj failed");
            return;
        }
        ani_ref configref = nullptr;
        status = ani_env_->GlobalReference_Create(configObj, &configref);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::APPKIT, "create configref failed, status: %{public}d", status);
            return;
        }

        ani_ref argv[] = {configref};
        ani_ref result;
        status = ani_env_->FunctionalObject_Call(OnConfigurationUpdatedFunc, 1, argv, &result);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::APPKIT, "FunctionalObject_Call failed, status: %{public}d", status);
            return;
        }
    }
}
} // namespace AbilityRuntime
} // namespace OHOS