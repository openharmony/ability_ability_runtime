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

#include "cj_insight_intent_context.h"

#include "ability_business_error.h"
#include "ability_window_configuration.h"
#include "cj_common_ffi.h"
#include "cj_insight_intent_executor_impl.h"
#include "cj_insight_intent_executor_impl_object.h"
#include "ffi_remote_data.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "want.h"
#include "want_params.h"

namespace OHOS {
namespace AbilityRuntime {

using WantHandle = void*;

int32_t CjInsightIntentContext::OnStartAbility(AAFwk::Want& want)
{
    TAG_LOGD(AAFwkTag::INTENT, "called");
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto context = context_.lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null context");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER);
    }
    // verify if bundleName is empty or invalid
    auto bundleNameFromWant = want.GetElement().GetBundleName();
    if (bundleNameFromWant.empty() || bundleNameFromWant != context->GetBundleName()) {
        TAG_LOGE(AAFwkTag::INTENT, "bundleName empty or invalid");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_OPERATION_NOT_SUPPORTED);
    }
    // modify windowmode setting
    auto windowMode = context->GetCurrentWindowMode();
    if (windowMode == AAFwk::AbilityWindowConfiguration::MULTI_WINDOW_DISPLAY_PRIMARY ||
        windowMode == AAFwk::AbilityWindowConfiguration::MULTI_WINDOW_DISPLAY_SECONDARY) {
        want.SetParam(AAFwk::Want::PARAM_RESV_WINDOW_MODE, windowMode);
    }
    auto innerErrCode = context->StartAbilityByInsightIntent(want);
    return static_cast<int32_t>(GetJsErrorCodeByNativeError(innerErrCode));
}

extern "C" {
CJ_EXPORT int32_t FFIInsightIntentGetContext(CJInsightIntentExecutorHandle executorHandle, int64_t* id)
{
    auto executor = static_cast<CJInsightIntentExecutorImpl*>(executorHandle);
    if (executor == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "GetCjInsightIntentContext failed, executor is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    if (id == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "GetCjInsightIntentContext failed, param id is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto context = executor->GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "GetCjInsightIntentContext failed, context is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto cjContext = OHOS::FFI::FFIData::Create<CjInsightIntentContext>(context);
    if (cjContext == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "GetCjInsightIntentContext failed, extAbilityContext is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    executor->SetCjContext(cjContext);
    *id = cjContext->GetID();
    return SUCCESS_CODE;
}

CJ_EXPORT int32_t FFIInsightIntentContextStartAbility(int64_t id, WantHandle want)
{
    auto context = OHOS::FFI::FFIData::GetData<CjInsightIntentContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto actualWant = reinterpret_cast<AAFwk::Want*>(want);
    return context->OnStartAbility(*actualWant);
}
}
} // namespace AbilityRuntime
} // namespace OHOS
