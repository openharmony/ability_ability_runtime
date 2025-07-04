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

#include "js_deferred_callback.h"

#include "ability_manager_errors.h"
#include "ability_business_error.h"
#include "hilog_tag_wrapper.h"
#include "js_error_utils.h"
#include "js_runtime_utils.h"

namespace OHOS {
namespace AbilityRuntime {
JsDeferredCallback::JsDeferredCallback(napi_env env): env_(env)
{
    if (env_ == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "null env_");
        return;
    }
    napi_create_promise(env_, &deferred_, &result);
}

void JsDeferredCallback::operator()(int32_t resultCode)
{
    if (deferred_ == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "null deferred_");
        return;
    }
    if (resultCode == ERR_OK) {
        napi_value value = CreateJsUndefined(env_);
        napi_resolve_deferred(env_, deferred_, value);
    } else {
        napi_value error = CreateJsError(env_, GetJsErrorCodeByNativeError(resultCode));
        napi_reject_deferred(env_, deferred_, error);
    }
}
} // namespace AbilityRuntime
} // namespace OHOS