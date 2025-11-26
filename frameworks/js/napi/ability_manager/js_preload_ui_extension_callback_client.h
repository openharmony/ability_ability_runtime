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
#ifndef OHOS_ABILITY_RUNTIME_JS_PRELOAD_UI_EXTENSION_CALLBACK_CLIENT_H
#define OHOS_ABILITY_RUNTIME_JS_PRELOAD_UI_EXTENSION_CALLBACK_CLIENT_H

#include "native_engine/native_reference.h"
#include "preload_ui_extension_callback_interface.h"

namespace OHOS {
namespace AbilityRuntime {
class JsPreloadUIExtensionCallbackClient : public PreloadUIExtensionCallbackInterface,
                                           public std::enable_shared_from_this<JsPreloadUIExtensionCallbackClient> {
public:
    JsPreloadUIExtensionCallbackClient(napi_env env, napi_ref ref) : env_(env), callbackRef_(ref) {}
    virtual ~JsPreloadUIExtensionCallbackClient();
    void ProcessOnLoadedDone(int32_t extensionAbilityId) override;
    void ProcessOnDestroyDone(int32_t extensionAbilityId) override;
    void CallJsPreloadedUIExtensionAbility(int32_t preloadId);

private:
    napi_env env_ = nullptr;
    napi_ref callbackRef_ = nullptr;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_JS_PRELOAD_UI_EXTENSION_CALLBACK_CLIENT_H
