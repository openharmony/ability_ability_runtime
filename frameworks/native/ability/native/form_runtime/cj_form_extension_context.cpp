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

#include "form_runtime/cj_form_extension.h"
#include "form_runtime/cj_form_extension_context.h"
#include "form_runtime/cj_form_extension_object.h"

#include <cinttypes>
#include <cstdint>
#include <charconv>

#include "hilog_tag_wrapper.h"
#include "form_mgr_errors.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace AbilityRuntime {

extern "C" {
CJ_EXPORT int32_t FFIFormExtAbilityGetContext(FormExtAbilityHandle extAbility, int64_t* id)
{
    auto ability = static_cast<CJFormExtension*>(extAbility);
    if (ability == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "GetCJFormExtensionContext failed, extAbility is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    if (id == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "GetCJFormExtensionContext failed, param id is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto context = ability->GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "GetCJFormExtensionContext failed, context is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto cjContext = OHOS::FFI::FFIData::Create<CJFormExtensionContext>(context);
    if (cjContext == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "GetCJFormExtensionContext failed, extAbilityContext is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    ability->SetCjContext(cjContext);
    *id = cjContext->GetID();
    return SUCCESS_CODE;
}
}
} // namespace AbilityRuntime
} // namespace OHOS
