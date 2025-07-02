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

#include "common_fun_ani.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {

bool SetExtensionAbilityInfo(ani_env *aniEnv, ani_class contextClass, ani_object contextObj,
    std::shared_ptr<Context> context, std::shared_ptr<AppExecFwk::AbilityInfo> abilityInfo)
{
    if (aniEnv == nullptr || context == nullptr || abilityInfo == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "aniEnv or context or abilityInfo is nullptr");
        return false;
    }
    auto hapModuleInfo = context->GetHapModuleInfo();
    if (hapModuleInfo == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null hapModuleInfo");
        return false;
    }
    ani_status status = ANI_OK;
    auto isExist = [&abilityInfo](const AppExecFwk::ExtensionAbilityInfo &info) {
        TAG_LOGD(AAFwkTag::CONTEXT, "%{public}s, %{public}s", info.bundleName.c_str(), info.name.c_str());
        return info.bundleName == abilityInfo->bundleName && info.name == abilityInfo->name;
    };
    ani_field extensionAbilityInfoField = nullptr;
    status = aniEnv->Class_FindField(contextClass, "extensionAbilityInfo", &extensionAbilityInfoField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "status: %{public}d", status);
        return false;
    }
    auto infoIter =
        std::find_if(hapModuleInfo->extensionInfos.begin(), hapModuleInfo->extensionInfos.end(), isExist);
    if (infoIter == hapModuleInfo->extensionInfos.end()) {
        TAG_LOGE(AAFwkTag::CONTEXT, "set extensionAbilityInfo fail");
        return false;
    }
    ani_object extAbilityInfoObj = AppExecFwk::CommonFunAni::ConvertExtensionInfo(aniEnv, *infoIter);
    status = aniEnv->Object_SetField_Ref(
        contextObj, extensionAbilityInfoField, reinterpret_cast<ani_ref>(extAbilityInfoObj));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "status: %{public}d", status);
        return false;
    }
    return true;
}

void CreateEtsExtensionContext(ani_env *aniEnv, ani_class contextClass, ani_object &contextObj,
    std::shared_ptr<ExtensionContext> context, std::shared_ptr<AppExecFwk::AbilityInfo> abilityInfo)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "CreateEtsExtensionContext Call");
    if (aniEnv == nullptr || context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "aniEnv or context is nullptr");
        return;
    }

    if (!SetExtensionAbilityInfo(aniEnv, contextClass, contextObj, context, abilityInfo)) {
        TAG_LOGE(AAFwkTag::CONTEXT, "SetExtensionAbilityInfo fail");
        return;
    }
}
} // namespace AbilityRuntime
} // namespace OHOS