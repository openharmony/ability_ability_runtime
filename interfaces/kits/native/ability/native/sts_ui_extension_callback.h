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

#ifndef OHOS_ABILITY_RUNTIME_STS_UI_EXTENSION_CALLBACK_H
#define OHOS_ABILITY_RUNTIME_STS_UI_EXTENSION_CALLBACK_H

#include "js_ui_extension_callback.h"
#include "sts_runtime.h"

namespace OHOS {
namespace Ace {
class UIContent;
}
namespace AbilityRuntime {
class StsUIExtensionCallback : public JsUIExtensionCallback,
    public std::enable_shared_from_this<StsUIExtensionCallback> {
public:
    StsUIExtensionCallback();
    virtual ~StsUIExtensionCallback();
    virtual void OnError(int32_t number);
    virtual void OnRelease(int32_t code);
    virtual void OnResult(int32_t resultCode, const AAFwk::Want &want);
    virtual void SetSessionId(int32_t sessionId);
    virtual void SetUIContent(Ace::UIContent* uiContent);
    virtual void SetStsCallbackObject(ani_vm* aniVM, ani_object aniObject);

private:
    ani_env* GetAniEnv();
    void CloseModalUIExtension();
    ani_vm* aniVM_ = nullptr;
    ani_ref startAbilityAniCallback_ = nullptr;
    int32_t aniSessionId_ = 0;
    Ace::UIContent* aniUIContent_ = nullptr;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_STS_UI_EXTENSION_CALLBACK_H