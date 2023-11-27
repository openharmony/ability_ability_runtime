/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_AUTO_FILL_EXTENSION_CALLBACK_H
#define OHOS_ABILITY_RUNTIME_AUTO_FILL_EXTENSION_CALLBACK_H

#include "fill_request_callback_interface.h"
#include "save_request_callback_interface.h"
#include "ui_content.h"
#include "want.h"

namespace OHOS {
namespace AbilityRuntime {
class AutoFillExtensionCallback {
public:
    AutoFillExtensionCallback() = default;
    ~AutoFillExtensionCallback() = default;

    void OnResult(int32_t errCode, const AAFwk::Want &want);
    void OnRelease(int32_t errCode);
    void OnError(int32_t errCode, const std::string &name, const std::string &message);

    void SetFillRequestCallback(const std::shared_ptr<IFillRequestCallback> &callback);
    void SetSaveRequestCallback(const std::shared_ptr<ISaveRequestCallback> &callback);

    void SetSessionId(int32_t sessionId);
    void SetUIContent(Ace::UIContent *uiContent);

private:
    void SendAutoFillSucess(const AAFwk::Want &want);
    void SendAutoFillFailed(int32_t errCode);
    std::shared_ptr<IFillRequestCallback> fillCallback_;
    std::shared_ptr<ISaveRequestCallback> saveCallback_;
    int32_t sessionId_;
    Ace::UIContent *uiContent_ = nullptr;
};
} // AbilityRuntime
} // OHOS
#endif // OHOS_ABILITY_RUNTIME_AUTO_FILL_EXTENSION_CALLBACK_H