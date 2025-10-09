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

#ifndef OHOS_ABILITY_RUNTIME_JS_APPLICATION_UTILS_H
#define OHOS_ABILITY_RUNTIME_JS_APPLICATION_UTILS_H

#include "native_engine/native_engine.h"

namespace OHOS {
namespace AbilityRuntime {
enum class AppPreloadType {
    UNSPECIFIED = 0,
    TYPE_CREATE_PROCESS = 1,
    TYPE_CREATE_ABILITY_STAGE = 2,
    TYPE_CREATE_WINDOW_STAGE = 3,
};

napi_value AppPreloadTypeInit(napi_env env);
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_JS_APPLICATION_UTILS_H
