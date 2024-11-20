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

#ifndef OHOS_ABILITY_RUNTIME_CJ_CONTEXT_ABILITY_LIFECYCLE_CALLBACK_H
#define OHOS_ABILITY_RUNTIME_CJ_CONTEXT_ABILITY_LIFECYCLE_CALLBACK_H

#include <cstdint>
#include <map>
#include <memory>
#include "cj_common_ffi.h"

using WindowStagePtr = void*;

namespace OHOS {
namespace AbilityRuntime {

class CjAbilityLifecycleCallback {
public:
    virtual ~CjAbilityLifecycleCallback() {}
    /**
     * Called back when the ability is started for initialization.
     *
     * @since 9
     * @syscap SystemCapability.Ability.AbilityRuntime.AbilityCore
     * @param ability: Indicates the ability to register for listening.
     * @StageModelOnly
     */
    virtual void OnAbilityCreate(const int64_t &ability) = 0;

    /**
     * Called back when the window stage is created.
     *
     * @since 9
     * @syscap SystemCapability.Ability.AbilityRuntime.AbilityCore
     * @param ability: Indicates the ability to register for listening.
     * @param windowStage: Indicates the window stage to create.
     * @StageModelOnly
     */
    virtual void OnWindowStageCreate(const int64_t &ability, WindowStagePtr windowStage) = 0;

    /**
     * Called back when the window stage is destroy.
     *
     * @since 9
     * @syscap SystemCapability.Ability.AbilityRuntime.AbilityCore
     * @param ability: Indicates the ability to register for listening.
     * @param windowStage: Indicates the window stage to destroy.
     * @StageModelOnly
     */
    virtual void OnWindowStageDestroy(const int64_t &ability,
        WindowStagePtr windowStage) = 0;

    /**
     * Called back when the window stage is active.
     *
     * @since 9
     * @syscap SystemCapability.Ability.AbilityRuntime.AbilityCore
     * @param ability: Indicates the ability to register for listening.
     * @param windowStage: Indicates the window stage to active.
     * @StageModelOnly
     */
    virtual void OnWindowStageActive(const int64_t &ability, WindowStagePtr windowStage) = 0;

    /**
     * Called back when the window stage is inactive.
     *
     * @since 9
     * @syscap SystemCapability.Ability.AbilityRuntime.AbilityCore
     * @param ability: Indicates the ability to register for listening.
     * @param windowStage: Indicates the window stage to inactive.
     * @StageModelOnly
     */
    virtual void OnWindowStageInactive(const int64_t &ability, WindowStagePtr windowStage) = 0;

    /**
     * Called back when the ability is destroy.
     *
     * @since 9
     * @syscap SystemCapability.Ability.AbilityRuntime.AbilityCore
     * @param ability: Indicates the ability to register for listening.
     * @StageModelOnly
     */
    virtual void OnAbilityDestroy(const int64_t &ability) = 0;

    /**
     * Called back after the UIAbility called onNewWant.
     *
     * @since 12
     * @syscap SystemCapability.Ability.AbilityRuntime.AbilityCore
     * @param ability: Indicates the ability to register for listening.
     * @StageModelOnly
     */
    virtual void OnNewWant(const int64_t &ability)
    {}

    /**
     * Called back before the UIAbility will called onNewWant.
     *
     * @since 12
     * @syscap SystemCapability.Ability.AbilityRuntime.AbilityCore
     * @param ability: Indicates the ability to register for listening.
     * @StageModelOnly
     */
    virtual void OnWillNewWant(const int64_t &ability)
    {}

    /**
     * Called back before an ability is started for initialization.
     *
     * @since 12
     * @syscap SystemCapability.Ability.AbilityRuntime.AbilityCore
     * @param ability: Indicates the ability to register for listening.
     * @StageModelOnly
     */
    virtual void OnAbilityWillCreate(const int64_t &ability)
    {}

    /**
     * Called back before a window stage is created.
     *
     * @since 12
     * @syscap SystemCapability.Ability.AbilityRuntime.AbilityCore
     * @param ability: Indicates the ability to register for listening.
     * @param windowStage: Indicates the window stage to active.
     * @StageModelOnly
     */
    virtual void OnWindowStageWillCreate(const int64_t &ability,
        WindowStagePtr windowStage) {}

    /**
     * Called back before a window stage is destroyed.
     *
     * @since 12
     * @syscap SystemCapability.Ability.AbilityRuntime.AbilityCore
     * @param ability: Indicates the ability to register for listening.
     * @param windowStage: Indicates the window stage to active.
     * @StageModelOnly
     */
    virtual void OnWindowStageWillDestroy(const int64_t &ability,
        WindowStagePtr windowStage) {}

    /**
     * Called back before an ability is destroyed.
     *
     * @since 12
     * @syscap SystemCapability.Ability.AbilityRuntime.AbilityCore
     * @param ability: Indicates the ability to register for listening.
     * @StageModelOnly
     */
    virtual void OnAbilityWillDestroy(const int64_t &ability) {}

    /**
     * Called back before the state of an ability changes to foreground.
     *
     * @since 12
     * @syscap SystemCapability.Ability.AbilityRuntime.AbilityCore
     * @param ability: Indicates the ability to register for listening.
     * @StageModelOnly
     */
    virtual void OnAbilityWillForeground(const int64_t &ability) {}

    /**
     * Called back before the state of an ability changes to background.
     *
     * @since 12
     * @syscap SystemCapability.Ability.AbilityRuntime.AbilityCore
     * @param ability: Indicates the ability to register for listening.
     * @StageModelOnly
     */
    virtual void OnAbilityWillBackground(const int64_t &ability) {}

    /**
     * Called back when the ability is foreground.
     *
     * @since 9
     * @syscap SystemCapability.Ability.AbilityRuntime.AbilityCore
     * @param ability: Indicates the ability to register for listening.
     * @StageModelOnly
     */
    virtual void OnAbilityForeground(const int64_t &ability) = 0;

    /**
     * Called back when the ability is background.
     *
     * @since 9
     * @syscap SystemCapability.Ability.AbilityRuntime.AbilityCore
     * @param ability: Indicates the ability to register for listening.
     * @StageModelOnly
     */
    virtual void OnAbilityBackground(const int64_t &ability) = 0;

    /**
     * Called back when the ability is continue.
     *
     * @since 9
     * @syscap SystemCapability.Ability.AbilityRuntime.AbilityCore
     * @param ability: Indicates the ability to register for listening.
     * @StageModelOnly
     */
    virtual void OnAbilityContinue(const int64_t &ability) = 0;

    virtual void OnAbilityWillContinue(const int64_t &ability) {}
    virtual void OnWindowStageWillRestore(const int64_t &ability,
        WindowStagePtr windowStage) {}
    virtual void OnWindowStageRestore(const int64_t &ability,
        WindowStagePtr windowStage) {}
    virtual void OnAbilityWillSaveState(const int64_t &ability) {}
    virtual void OnAbilitySaveState(const int64_t &ability) {}
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_CJ_CONTEXT_ABILITY_LIFECYCLE_CALLBACK_H