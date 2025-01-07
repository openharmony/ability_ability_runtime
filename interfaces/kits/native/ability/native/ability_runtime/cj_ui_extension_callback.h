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

#ifndef OHOS_ABILITY_RUNTIME_CJ_UI_EXTENSION_CALLBACK_H
#define OHOS_ABILITY_RUNTIME_CJ_UI_EXTENSION_CALLBACK_H

#include "cj_ability_context_utils.h"

#include "want.h"

namespace OHOS {
namespace Ace {
class UIContent;
}

namespace AbilityRuntime {
class CjUIExtensionCallback : public std::enable_shared_from_this<CjUIExtensionCallback> {
public:
    explicit CjUIExtensionCallback() {}
    void OnError(int32_t number);
    void OnRelease(int32_t code);
    void OnResult(int32_t resultCode, const AAFwk::Want &want);
    void CallCjResult(int32_t resultCode, const AAFwk::Want &want);
    void SetCjCallbackOnResult(std::function<void(CJAbilityResult)> onResultCallback);
    void SetCjCallbackOnError(std::function<void(int32_t, char*, char*)> onErrorCallback);
    void CallCjError(int32_t number);
    void SetSessionId(int32_t sessionId);
    void SetUIContent(Ace::UIContent* uiContent);
private:
    std::function<void(CJAbilityResult)> onResultCallback_;
    std::function<void(int32_t, char*, char*)> onErrorCallback_;
    int32_t sessionId_ = 0;
    Ace::UIContent* uiContent_ = nullptr;
};
} // AbilityRuntime
} // OHOS

#endif // OHOS_ABILITY_RUNTIME_CJ_UI_EXTENSION_CALLBACK_H
