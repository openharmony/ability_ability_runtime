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

#ifndef OHOS_ABILITY_RUNTIME_PANEL_START_CALLBACK_H
#define OHOS_ABILITY_RUNTIME_PANEL_START_CALLBACK_H

#include <string>

#include "want.h"

namespace OHOS {
namespace Ace {
class UIContent;
}
namespace AbilityRuntime {
class PanelStartCallback {
public:
    PanelStartCallback() = default;
    virtual ~PanelStartCallback() = default;
    void SetSessionId(int32_t sessionId);
#ifdef SUPPORT_SCREEN
    virtual void OnError(int32_t number) = 0;
    virtual void OnResult(int32_t resultCode, const AAFwk::Want &want) = 0;
    void OnRelease(int32_t code);
    void SetUIContent(Ace::UIContent *uiContent);
    void CloseModalUIExtension();
#endif // SUPPORT_SCREEN
private:
    int32_t sessionId_ = 0;
#ifdef SUPPORT_SCREEN
    Ace::UIContent *uiContent_ = nullptr;
#endif // SUPPORT_SCREEN
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_PANEL_START_CALLBACK_H
