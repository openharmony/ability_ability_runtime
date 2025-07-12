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
#include "ui_extension_callback.h"

#include "hilog_tag_wrapper.h"
#ifdef SUPPORT_SCREEN
#include "ui_content.h"
#include "ws_common.h"
#endif // SUPPORT_SCREEN

namespace OHOS {
namespace AbilityRuntime {
void UIExtensionCallback::SetSessionId(int32_t sessionId)
{
    sessionId_ = sessionId;
}
#ifdef SUPPORT_SCREEN
void UIExtensionCallback::SetUIContent(Ace::UIContent* uiContent)
{
    uiContent_ = uiContent;
}

void UIExtensionCallback::OnRelease(int32_t code)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "call, code:%{public}d", code);
    CloseModalUIExtension();
}

void UIExtensionCallback::CloseModalUIExtension()
{
    if (uiContent_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null uiContent_");
        return;
    }
    uiContent_->CloseModalUIExtension(sessionId_);
}
#endif // SUPPORT_SCREEN
} // namespace AbilityRuntime
} // namespace OHOS
