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
#include <shared_mutex>

#include "cj_macro.h"
#include "cj_environment_callback.h"
#include "cj_ability_lifecycle_callback.h"
#include "cj_application_state_change_callback.h"
#include "cj_common_ffi.h"
#include "ffi_remote_data.h"
#include "ability_delegator_registry.h"

namespace OHOS {
namespace ApplicationContextCJ {
using namespace OHOS::AbilityRuntime;

class CJApplicationContext : public FFI::FFIData {
public:
    explicit CJApplicationContext(std::weak_ptr<AbilityRuntime::ApplicationContext> &&applicationContext)
        : applicationContext_(std::move(applicationContext)) {};

    int GetArea();
    std::shared_ptr<AppExecFwk::ApplicationInfo> GetApplicationInfo();
    void RegisterAbilityLifecycleCallback(const std::shared_ptr<CjAbilityLifecycleCallback> &abilityLifecycleCallback);
    void UnregisterAbilityLifecycleCallback(
        const std::shared_ptr<CjAbilityLifecycleCallback> &abilityLifecycleCallback);
    bool IsAbilityLifecycleCallbackEmpty();
    void DispatchOnAbilityCreate(const int64_t &ability);
    void DispatchOnWindowStageCreate(const int64_t &ability, WindowStagePtr windowStage);
    void DispatchWindowStageFocus(const int64_t &ability, WindowStagePtr windowStage);
    void DispatchWindowStageUnfocus(const int64_t &ability, WindowStagePtr windowStage);
    void DispatchOnWindowStageDestroy(const int64_t &ability, WindowStagePtr windowStage);
    void DispatchOnAbilityDestroy(const int64_t &ability);
    void DispatchOnAbilityForeground(const int64_t &ability);
    void DispatchOnAbilityBackground(const int64_t &ability);
    void DispatchOnAbilityContinue(const int64_t &ability);
    // optional callbacks
    void DispatchOnAbilityWillCreate(const int64_t &ability);
    void DispatchOnWindowStageWillCreate(const int64_t &ability, WindowStagePtr windowStage);
    void DispatchOnWindowStageWillDestroy(const int64_t &ability, WindowStagePtr windowStage);
    void DispatchOnAbilityWillDestroy(const int64_t &ability);
    void DispatchOnAbilityWillForeground(const int64_t &ability);
    void DispatchOnAbilityWillBackground(const int64_t &ability);
    void DispatchOnNewWant(const int64_t &ability);
    void DispatchOnWillNewWant(const int64_t &ability);
    void DispatchOnAbilityWillContinue(const int64_t &ability);
    void DispatchOnWindowStageWillRestore(const int64_t &ability, WindowStagePtr windowStage);
    void DispatchOnWindowStageRestore(const int64_t &ability, WindowStagePtr windowStage);
    void DispatchOnAbilityWillSaveState(const int64_t &ability);
    void DispatchOnAbilitySaveState(const int64_t &ability);

    int32_t OnOnEnvironment(void (*cfgCallback)(AbilityRuntime::CConfiguration),
        void (*memCallback)(int32_t), bool isSync, int32_t *errCode);
    int32_t OnOnAbilityLifecycle(CArrI64 cFuncIds, bool isSync, int32_t *errCode);
    int32_t OnOnApplicationStateChange(void (*foregroundCallback)(void),
        void (*backgroundCallback)(void), int32_t *errCode);
    void OnOffEnvironment(int32_t callbackId, int32_t *errCode);
    void OnOffAbilityLifecycle(int32_t callbackId, int32_t *errCode);
    void OnOffApplicationStateChange(int32_t callbackId, int32_t *errCode);
    static CJApplicationContext* GetCJApplicationContext(
        std::weak_ptr<AbilityRuntime::ApplicationContext> &&applicationContext);
private:
    std::weak_ptr<AbilityRuntime::ApplicationContext> applicationContext_;
    std::shared_ptr<AbilityRuntime::CjAbilityLifecycleCallback> callback_;
    std::shared_ptr<AbilityRuntime::CjEnvironmentCallback> envCallback_;
    std::shared_ptr<CjApplicationStateChangeCallback> applicationStateCallback_;
    std::mutex applicationStateCallbackLock_;
    std::recursive_mutex callbackLock_;
    static std::vector<std::shared_ptr<CjAbilityLifecycleCallback>> callbacks_;
    static CJApplicationContext* cjApplicationContext_;
};

extern "C" {
struct CApplicationInfo {
    const char* name;
    const char* bundleName;
};

CJ_EXPORT int64_t FFIGetArea(int64_t id);
CJ_EXPORT CApplicationInfo* FFICJApplicationInfo(int64_t id);
CJ_EXPORT int32_t FfiCJApplicationContextOnOnEnvironment(int64_t id, void (*cfgCallback)(CConfiguration),
    void (*memCallback)(int32_t), int32_t *errCode);
CJ_EXPORT int32_t FfiCJApplicationContextOnOnAbilityLifecycle(int64_t id, CArrI64 cFuncIds, int32_t *errCode);
CJ_EXPORT int32_t FfiCJApplicationContextOnOnApplicationStateChange(int64_t id, void (*foregroundCallback)(void),
    void (*backgroundCallback)(void), int32_t *errCode);
CJ_EXPORT void FfiCJApplicationContextOnOff(int64_t id, const char* type, int32_t callbackId, int32_t *errCode);
};
}
}
#endif // OHOS_ABILITY_RUNTIME_CJ_APPLICATION_CONTEXT_H