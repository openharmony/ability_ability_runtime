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

#include "auto_fill_extension_context.h"

#include "hilog_tag_wrapper.h"
#include "js_auto_fill_extension_util.h"

namespace OHOS {
namespace AbilityRuntime {
const size_t AutoFillExtensionContext::CONTEXT_TYPE_ID(std::hash<const char*> {} ("AutoFillExtensionContext"));

void AutoFillExtensionContext::SetAutoFillExtensionCallback(
    const std::weak_ptr<IAutoFillExtensionCallback> &autoFillExtensionCallback)
{
    autoFillExtensionCallback_ = autoFillExtensionCallback;
}

void AutoFillExtensionContext::SetSessionInfo(const sptr<AAFwk::SessionInfo> &sessionInfo)
{
    sessionInfo_ = sessionInfo;
}

int32_t AutoFillExtensionContext::ReloadInModal(const CustomData &customData)
{
    TAG_LOGD(AAFwkTag::AUTOFILL_EXT, "called");
    if (sessionInfo_ == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null sessionInfo_");
        return ERR_NULL_OBJECT;
    }
    auto autoFillExtensionCallback = autoFillExtensionCallback_.lock();
    if (autoFillExtensionCallback == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null autoFillExtensionCallback");
        return ERR_NULL_OBJECT;
    }
    return autoFillExtensionCallback->OnReloadInModal(sessionInfo_, customData);
}

bool AutoFillExtensionContext::IsContext(size_t contextTypeId)
{
    return contextTypeId == CONTEXT_TYPE_ID || UIExtensionContext::IsContext(contextTypeId);
}
} // namespace AbilityRuntime
} // namespace OHOS
