/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "cj_ability_stage_context.h"
#include "ffi_remote_data.h"
#include "hap_module_info.h"
#include "ability_runtime/context/context.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {

RetHapModuleInfo CJAbilityStageContext::GetRetHapModuleInfo()
{
    auto context = GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "context is null, getHapModuleInfo failed. ");
        return RetHapModuleInfo();
    }

    auto hapInfo = context->GetHapModuleInfo();
    if (hapInfo == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "CurrentHapMoudleInfo is nullptr.");
        return RetHapModuleInfo();
    }

    return OHOS::CJSystemapi::BundleManager::Convert::ConvertHapModuleInfo(*hapInfo);
}

std::shared_ptr<AppExecFwk::HapModuleInfo> CJAbilityStageContext::GetHapModuleInfo()
{
    auto context = GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "context is null, getHapModuleInfo failed. ");
        return nullptr;
    }
    return context->GetHapModuleInfo();
}

CConfiguration CJAbilityStageContext::GetConfiguration()
{
    auto context = GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "context is null, getConfiguration failed. ");
        return CConfiguration();
    }

    auto configuration = context->GetConfiguration();
    if (configuration == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "CurrentConfiguration is nullptr.");
        return CConfiguration();
    }

    return CreateCConfiguration(*configuration);
}

}
}