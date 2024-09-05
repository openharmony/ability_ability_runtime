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

#ifndef OHOS_ABILITY_RUNTIME_CJ_APPLICATION_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_CJ_APPLICATION_CONTEXT_H

#include <cstdint>

#include "cj_macro.h"
#include "cj_environment_callback.h"
#include "ffi_remote_data.h"
#include "ability_delegator_registry.h"

namespace OHOS {
namespace ApplicationContextCJ {
class CJApplicationContext : public FFI::FFIData {
public:
    explicit CJApplicationContext(std::weak_ptr<AbilityRuntime::ApplicationContext> &&applicationContext)
        : applicationContext_(std::move(applicationContext)) {};

    int GetArea();
    std::shared_ptr<AppExecFwk::ApplicationInfo> GetApplicationInfo();
    int32_t OnOnEnvironment(void (*cfgCallback)(AbilityRuntime::CConfiguration),
        void (*memCallback)(int32_t), bool isSync, int32_t *errCode);
    void OnOffEnvironment(int32_t callbackId, int32_t *errCode);

private:
    std::weak_ptr<AbilityRuntime::ApplicationContext> applicationContext_;
    std::shared_ptr<AbilityRuntime::CjEnvironmentCallback> envCallback_;
};

extern "C" {
struct CApplicationInfo {
    const char* name;
    const char* bundleName;
};

CJ_EXPORT int64_t FFIGetArea(int64_t id);
CJ_EXPORT CApplicationInfo* FFICJApplicationInfo(int64_t id);
CJ_EXPORT int32_t FFICJApplicationContextOnOn(int64_t id, char* type,
    void (*cfgCallback)(AbilityRuntime::CConfiguration), void (*memCallback)(int32_t), int32_t *errCode);
CJ_EXPORT void FFICJApplicationContextOnOff(int64_t id, char* type, int32_t callbackId, int32_t *errCode);
};
}
}
#endif // OHOS_ABILITY_RUNTIME_CJ_APPLICATION_CONTEXT_H