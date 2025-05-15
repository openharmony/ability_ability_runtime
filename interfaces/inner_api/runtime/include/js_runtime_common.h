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

#ifndef ABILITY_ABILITY_RUNTIME_JS_RUNTIME_COMMON_H
#define ABILITY_ABILITY_RUNTIME_JS_RUNTIME_COMMON_H

#include "native_engine/native_engine.h"

namespace OHOS {
namespace AbilityRuntime {
class JsRuntimeCommon {
public:
    JsRuntimeCommon(const JsRuntimeCommon&) = delete;
    JsRuntimeCommon& operator=(const JsRuntimeCommon&) = delete;
    static JsRuntimeCommon& GetInstance();
    bool IsDebugMode();
    bool IsDebugApp();
    bool IsNativeStart();
    void SetDebugMode(bool isDebugMode);
    void SetDebugApp(bool isDebugApp);
    void SetNativeStart(bool isNativeStart);
    napi_status StartDebugMode(NativeEngine* nativeEngine, const std::string& threadName);
    napi_status StopDebugMode(NativeEngine* nativeEngine);
    void StartDebuggerModule(bool isDebugApp, bool isNativeStart);

private:
    JsRuntimeCommon();
    ~JsRuntimeCommon();
    bool debugMode_ = false;
    bool debugApp_ = false;
    bool nativeStart_ = false;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // ABILITY_ABILITY_RUNTIME_JS_RUNTIME_COMMON_H
