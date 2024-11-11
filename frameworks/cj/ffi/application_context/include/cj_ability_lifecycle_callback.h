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
#include "ability_lifecycle_callback.h"

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

class CjAbilityLifecycleCallbackImpl : public CjAbilityLifecycleCallback,
                                       public std::enable_shared_from_this<CjAbilityLifecycleCallbackImpl> {
public:
    explicit CjAbilityLifecycleCallbackImpl() {};
    virtual ~CjAbilityLifecycleCallbackImpl() {};

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
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_CJ_CONTEXT_ABILITY_LIFECYCLE_CALLBACK_H