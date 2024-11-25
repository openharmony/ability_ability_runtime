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

#ifndef OHOS_ABILITY_RUNTIME_CJ_CONTEXT_ABILITY_LIFECYCLE_CALLBACK_IMPL_H
#define OHOS_ABILITY_RUNTIME_CJ_CONTEXT_ABILITY_LIFECYCLE_CALLBACK_IMPL_H

#include <cstdint>
#include <map>
#include <memory>

#include "ability_lifecycle_callback.h"
#include "cj_ability_lifecycle_callback.h"
#include "cj_common_ffi.h"

using WindowStagePtr = void *;

namespace OHOS {
namespace AbilityRuntime {

class CjAbilityLifecycleCallbackImpl : public CjAbilityLifecycleCallback,
                                       public std::enable_shared_from_this<CjAbilityLifecycleCallbackImpl> {
public:
    explicit CjAbilityLifecycleCallbackImpl(){};
    virtual ~CjAbilityLifecycleCallbackImpl(){};

    void OnAbilityCreate(const int64_t &ability) override;
    void OnWindowStageCreate(const int64_t &ability, WindowStagePtr windowStage) override;
    void OnWindowStageActive(const int64_t &ability, WindowStagePtr windowStage) override;
    void OnWindowStageInactive(const int64_t &ability, WindowStagePtr windowStage) override;
    void OnWindowStageDestroy(const int64_t &ability, WindowStagePtr windowStage) override;
    void OnAbilityDestroy(const int64_t &ability) override;
    void OnAbilityForeground(const int64_t &ability) override;
    void OnAbilityBackground(const int64_t &ability) override;
    void OnAbilityContinue(const int64_t &ability) override;
    // optional callbacks
    void OnAbilityWillCreate(const int64_t &ability) override;
    void OnWindowStageWillCreate(const int64_t &ability, WindowStagePtr windowStage) override;
    void OnWindowStageWillDestroy(const int64_t &ability, WindowStagePtr windowStage) override;
    void OnAbilityWillDestroy(const int64_t &ability) override;
    void OnAbilityWillForeground(const int64_t &ability) override;
    void OnAbilityWillBackground(const int64_t &ability) override;
    void OnNewWant(const int64_t &ability) override;
    void OnWillNewWant(const int64_t &ability) override;
    void OnAbilityWillContinue(const int64_t &ability) override;
    void OnWindowStageWillRestore(const int64_t &ability, WindowStagePtr windowStage) override;
    void OnWindowStageRestore(const int64_t &ability, WindowStagePtr windowStage) override;
    void OnAbilityWillSaveState(const int64_t &ability) override;
    void OnAbilitySaveState(const int64_t &ability) override;

    int32_t Register(CArrI64 cFuncIds, bool isSync = false);
    bool UnRegister(int32_t callbackId, bool isSync = false);
    bool IsEmpty() const;
    static int32_t serialNumber_;

private:
    std::map<int32_t, std::function<void(int64_t)>> onAbilityCreatecallbacks_;
    std::map<int32_t, std::function<void(int64_t, WindowStagePtr)>> onWindowStageCreatecallbacks_;
    std::map<int32_t, std::function<void(int64_t, WindowStagePtr)>> onWindowStageActivecallbacks_;
    std::map<int32_t, std::function<void(int64_t, WindowStagePtr)>> onWindowStageInactivecallbacks_;
    std::map<int32_t, std::function<void(int64_t, WindowStagePtr)>> onWindowStageDestroycallbacks_;
    std::map<int32_t, std::function<void(int64_t)>> onAbilityDestroycallbacks_;
    std::map<int32_t, std::function<void(int64_t)>> onAbilityForegroundcallbacks_;
    std::map<int32_t, std::function<void(int64_t)>> onAbilityBackgroundcallbacks_;
    std::map<int32_t, std::function<void(int64_t)>> onAbilityContinuecallbacks_;
    // optional callbacks
    std::map<int32_t, std::function<void(int64_t)>> onAbilityWillCreatecallbacks_;
    std::map<int32_t, std::function<void(int64_t, WindowStagePtr)>> onWindowStageWillCreatecallbacks_;
    std::map<int32_t, std::function<void(int64_t, WindowStagePtr)>> onWindowStageWillDestroycallbacks_;
    std::map<int32_t, std::function<void(int64_t)>> onAbilityWillForegroundcallbacks_;
    std::map<int32_t, std::function<void(int64_t)>> onAbilityWillDestroycallbacks_;
    std::map<int32_t, std::function<void(int64_t)>> onAbilityWillBackgroundcallbacks_;
    std::map<int32_t, std::function<void(int64_t)>> onWillNewWantcallbacks_;
    std::map<int32_t, std::function<void(int64_t)>> onNewWantcallbacks_;
    std::map<int32_t, std::function<void(int64_t)>> onAbilityWillContinuecallbacks_;
    std::map<int32_t, std::function<void(int64_t, WindowStagePtr)>> onWindowStageWillRestorecallbacks_;
    std::map<int32_t, std::function<void(int64_t, WindowStagePtr)>> onWindowStageRestorecallbacks_;
    std::map<int32_t, std::function<void(int64_t)>> onAbilityWillSaveStatecallbacks_;
    std::map<int32_t, std::function<void(int64_t)>> onAbilitySaveStatecallbacks_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_CJ_CONTEXT_ABILITY_LIFECYCLE_CALLBACK_H