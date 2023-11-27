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

#ifndef OHOS_ABILITY_RUNTIME_JS_AUTO_FILL_EXTENSION_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_JS_AUTO_FILL_EXTENSION_CONTEXT_H

#include <memory>

#include "auto_fill_extension_context.h"
#include "native_engine/native_engine.h"

namespace OHOS {
namespace AbilityRuntime {
struct NapiCallbackInfo;
class JsAutoFillExtensionContext {
public:
    JsAutoFillExtensionContext() = default;
    virtual ~JsAutoFillExtensionContext() = default;

    static void Finalizer(napi_env env, void *data, void *hint);
    static napi_value CreateJsAutoFillExtensionContext(
        napi_env env, const std::shared_ptr<AutoFillExtensionContext> &context);
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_JS_AUTO_FILL_EXTENSION_CONTEXT_H