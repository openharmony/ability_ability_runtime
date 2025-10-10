/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_CONTEXT_ABILITY_LIFECYCLE_CALLBACK_H
#define OHOS_ABILITY_RUNTIME_CONTEXT_ABILITY_LIFECYCLE_CALLBACK_H

#include <map>
#include <memory>

namespace OHOS {
namespace AbilityRuntime {
enum AbilityLifecycleCallbackType {
    JS = 0,
    ETS,
};
class AbilityLifecycleCallbackArgs {
public:
    AbilityLifecycleCallbackType type_ = AbilityLifecycleCallbackType::JS;
    virtual bool IsValid() const { return true; }
};

class AbilityLifecycleCallback {
public:
    virtual ~AbilityLifecycleCallback() {}
    virtual void OnAbilityCreate(const AbilityLifecycleCallbackArgs &ability) {}
    virtual void OnWindowStageCreate(const AbilityLifecycleCallbackArgs &ability,
        const AbilityLifecycleCallbackArgs &windowStage) {}
    virtual void OnWindowStageDestroy(const AbilityLifecycleCallbackArgs &ability,
        const AbilityLifecycleCallbackArgs &windowStage) {}
    virtual void OnWindowStageActive(const AbilityLifecycleCallbackArgs &ability,
        const AbilityLifecycleCallbackArgs &windowStage) {}
    virtual void OnWindowStageInactive(const AbilityLifecycleCallbackArgs &ability,
        const AbilityLifecycleCallbackArgs &windowStage) {}
    virtual void OnAbilityDestroy(const AbilityLifecycleCallbackArgs &ability) {}
    virtual void OnNewWant(const AbilityLifecycleCallbackArgs &ability) {}
    virtual void OnWillNewWant(const AbilityLifecycleCallbackArgs &ability) {}
    virtual void OnAbilityWillCreate(const AbilityLifecycleCallbackArgs &ability) {}
    virtual void OnWindowStageWillCreate(const AbilityLifecycleCallbackArgs &ability,
        const AbilityLifecycleCallbackArgs &windowStage) {}
    virtual void OnWindowStageWillDestroy(const AbilityLifecycleCallbackArgs &ability,
        const AbilityLifecycleCallbackArgs &windowStage) {}
    virtual void OnAbilityWillDestroy(const AbilityLifecycleCallbackArgs &ability) {}
    virtual void OnAbilityWillForeground(const AbilityLifecycleCallbackArgs &ability) {}
    virtual void OnAbilityWillBackground(const AbilityLifecycleCallbackArgs &ability) {}
    virtual void OnAbilityForeground(const AbilityLifecycleCallbackArgs &ability) {}
    virtual void OnAbilityBackground(const AbilityLifecycleCallbackArgs &ability) {}
    virtual void OnAbilityContinue(const AbilityLifecycleCallbackArgs &ability) {}
    virtual void OnAbilityWillContinue(const AbilityLifecycleCallbackArgs &ability) {}
    virtual void OnWindowStageWillRestore(const AbilityLifecycleCallbackArgs &ability,
        const AbilityLifecycleCallbackArgs &windowStage) {}
    virtual void OnWindowStageRestore(const AbilityLifecycleCallbackArgs &ability,
        const AbilityLifecycleCallbackArgs &windowStage) {}
    virtual void OnAbilityWillSaveState(const AbilityLifecycleCallbackArgs &ability) {}
    virtual void OnAbilitySaveState(const AbilityLifecycleCallbackArgs &ability) {}
    virtual void OnWillForeground(const AbilityLifecycleCallbackArgs &ability) {}
    virtual void OnDidForeground(const AbilityLifecycleCallbackArgs &ability) {}
    virtual void OnWillBackground(const AbilityLifecycleCallbackArgs &ability) {}
    virtual void OnDidBackground(const AbilityLifecycleCallbackArgs &ability) {}

public:
    AbilityLifecycleCallbackType type_ = AbilityLifecycleCallbackType::JS;
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_CONTEXT_ABILITY_LIFECYCLE_CALLBACK_H