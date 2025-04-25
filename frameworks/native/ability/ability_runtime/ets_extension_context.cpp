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

#include "ets_extension_context.h"
#include "ani_common_configuration.h"
#include "hilog_tag_wrapper.h"
#include "common_fun_ani.h"
#include "sts_context_utils.h"

namespace OHOS {
namespace AbilityRuntime {

bool SetExtensionAbilityInfo(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    std::shared_ptr<OHOS::AbilityRuntime::Context> context, std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo)
{
    bool iRet = false;
    if (aniEnv == nullptr || context == nullptr || abilityInfo == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "aniEnv or context or abilityInfo is nullptr");
        return iRet;
    }
    auto hapModuleInfo = context->GetHapModuleInfo();
    ani_status status = ANI_OK;
    if (abilityInfo && hapModuleInfo) {
        auto isExist = [&abilityInfo](const OHOS::AppExecFwk::ExtensionAbilityInfo& info) {
            TAG_LOGD(AAFwkTag::CONTEXT, "%{public}s, %{public}s", info.bundleName.c_str(), info.name.c_str());
            return info.bundleName == abilityInfo->bundleName && info.name == abilityInfo->name;
        };
        auto infoIter = std::find_if(
            hapModuleInfo->extensionInfos.begin(), hapModuleInfo->extensionInfos.end(), isExist);
        if (infoIter == hapModuleInfo->extensionInfos.end()) {
            TAG_LOGE(AAFwkTag::CONTEXT, "set extensionAbilityInfo fail");
            return iRet;
        }
        ani_field extensionAbilityInfoField;
        status = aniEnv->Class_FindField(contextClass, "extensionAbilityInfo", &extensionAbilityInfoField);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::CONTEXT, "status: %{public}d", status);
            return iRet;
        }
        ani_object extAbilityInfoObj = OHOS::AppExecFwk::CommonFunAni::ConvertExtensionInfo(aniEnv, *infoIter);
        status = aniEnv->Object_SetField_Ref(contextObj, extensionAbilityInfoField,
            reinterpret_cast<ani_ref>(extAbilityInfoObj));
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::CONTEXT, "status: %{public}d", status);
            return iRet;
        }
        iRet = true;
    }
    return iRet;
}

bool SetConfiguration(
    ani_env *env, ani_class cls, ani_object contextObj, const std::shared_ptr<OHOS::AbilityRuntime::Context> &context)
{
    if (env == nullptr || context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "aniEnv or context is nullptr");
        return false;
    }

    ani_field field = nullptr;
    auto configuration = context->GetConfiguration();
    ani_ref configurationRef = OHOS::AppExecFwk::WrapConfiguration(env, *configuration);

    ani_status status = env->Class_FindField(cls, "config", &field);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "status: %{public}d", status);
        return false;
    }

    status = env->Object_SetField_Ref(contextObj, field, configurationRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "status: %{public}d", status);
        return false;
    }
    return true;
}

void CreatEtsExtensionContext(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    std::shared_ptr<OHOS::AbilityRuntime::ExtensionContext> context,
    std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "CreatEtsExtensionContext Call");
    if (aniEnv == nullptr || context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "aniEnv or context is nullptr");
        return;
    }

    if (!SetExtensionAbilityInfo(aniEnv, contextClass, contextObj, context, abilityInfo)) {
        TAG_LOGE(AAFwkTag::CONTEXT, "SetExtensionAbilityInfo fail");
        return;
    }

    if (!SetConfiguration(aniEnv, contextClass, contextObj, context)) {
        TAG_LOGE(AAFwkTag::CONTEXT, "SetConfiguration fail");
        return;
    }
}
} // namespace AbilityRuntime
} // namespace OHOS