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

#ifndef OHOS_ABILITY_RUNTIME_JS_APP_SERVICE_EXTENSION_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_JS_APP_SERVICE_EXTENSION_CONTEXT_H

#include <memory>

#include "ability_connect_callback.h"
#include "app_service_extension_context.h"
#include "event_handler.h"
#include "js_free_install_observer.h"
#include "native_engine/native_engine.h"
#include "js_service_extension_context.h"

namespace OHOS {
namespace AbilityRuntime {
napi_value CreateJsAppServiceExtensionContext(napi_env env, std::shared_ptr<AppServiceExtensionContext> context);

class JSAppServiceExtensionConnection : public JSServiceExtensionConnection {
public:
    explicit JSAppServiceExtensionConnection(napi_env env) : JSServiceExtensionConnection(env) {}
    virtual ~JSAppServiceExtensionConnection() {}
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_JS_APP_SERVICE_EXTENSION_CONTEXT_H