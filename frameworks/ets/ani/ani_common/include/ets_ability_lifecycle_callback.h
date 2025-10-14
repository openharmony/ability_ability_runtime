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

#ifndef OHOS_ABILITY_RUNTIME_CONTEXT_ETS_ABILITY_LIFECYCLE_CALLBACK_H
#define OHOS_ABILITY_RUNTIME_CONTEXT_ETS_ABILITY_LIFECYCLE_CALLBACK_H

#include <map>
#include <memory>
#include <mutex>

#include "ability_lifecycle_callback.h"
#include "ani.h"

namespace OHOS {
namespace AppExecFwk {
struct ETSNativeReference;
}  // namespace AppExecFwk
namespace AbilityRuntime {
class EtsAbilityLifecycleCallbackArgs : public AbilityLifecycleCallbackArgs {
public:
    explicit EtsAbilityLifecycleCallbackArgs(const std::shared_ptr<AppExecFwk::ETSNativeReference> &ref) : ref_(ref)
    {
        type_ = AbilityLifecycleCallbackType::ETS;
    }
    bool IsValid() const override { return ref_ != nullptr; }
    const std::shared_ptr<AppExecFwk::ETSNativeReference> &ref_;
};

class EtsAbilityLifecycleCallback : public AbilityLifecycleCallback,
                                    public std::enable_shared_from_this<EtsAbilityLifecycleCallback> {
public:
    explicit EtsAbilityLifecycleCallback(ani_env *env);
    void OnAbilityCreate(const AbilityLifecycleCallbackArgs &ability) override;
    void OnWindowStageCreate(const AbilityLifecycleCallbackArgs &ability,
        const AbilityLifecycleCallbackArgs &windowStage) override;
    void OnWindowStageDestroy(const AbilityLifecycleCallbackArgs &ability,
        const AbilityLifecycleCallbackArgs &windowStage) override;
    void OnAbilityDestroy(const AbilityLifecycleCallbackArgs &ability) override;
    void OnAbilityForeground(const AbilityLifecycleCallbackArgs &ability) override;
    void OnAbilityBackground(const AbilityLifecycleCallbackArgs &ability) override;
    void OnAbilitySaveState(const AbilityLifecycleCallbackArgs &ability) override;
    void OnWindowStageRestore(const AbilityLifecycleCallbackArgs &ability,
        const AbilityLifecycleCallbackArgs &windowStage) override;
    void OnAbilityWillDestroy(const AbilityLifecycleCallbackArgs &ability) override;
    void OnWindowStageWillDestroy(const AbilityLifecycleCallbackArgs &ability,
        const AbilityLifecycleCallbackArgs &windowStage) override;
    void OnWindowStageWillCreate(const AbilityLifecycleCallbackArgs &ability,
        const AbilityLifecycleCallbackArgs &windowStage) override;
    void OnAbilityWillBackground(const AbilityLifecycleCallbackArgs &ability) override;
    void OnWindowStageWillRestore(const AbilityLifecycleCallbackArgs &ability,
        const AbilityLifecycleCallbackArgs &windowStage) override;
    void OnAbilityWillCreate(const AbilityLifecycleCallbackArgs &ability) override;
    void OnAbilityWillForeground(const AbilityLifecycleCallbackArgs &ability) override;
    void OnNewWant(const AbilityLifecycleCallbackArgs &ability) override;
    void OnAbilityWillContinue(const AbilityLifecycleCallbackArgs &ability) override;
    void OnWillNewWant(const AbilityLifecycleCallbackArgs &ability) override;
    void OnAbilityWillSaveState(const AbilityLifecycleCallbackArgs &ability) override;
    void OnAbilityContinue(const AbilityLifecycleCallbackArgs &ability) override;
    void OnWindowStageInactive(const AbilityLifecycleCallbackArgs &ability,
        const AbilityLifecycleCallbackArgs &windowStage) override;
    void OnWindowStageActive(const AbilityLifecycleCallbackArgs &ability,
        const AbilityLifecycleCallbackArgs &windowStage) override;

    int32_t Register(ani_object callback);
    bool Unregister(int32_t callbackId);
    bool IsEmpty() const;

private:
    ani_env *GetAniEnv();
    void CallObjectMethod(const char *methodName, const char *signature,
        std::shared_ptr<AppExecFwk::ETSNativeReference> ability);
    void CallObjectMethod(const char *methodName, const char *signature,
        std::shared_ptr<AppExecFwk::ETSNativeReference> ability,
        std::shared_ptr<AppExecFwk::ETSNativeReference> windowStage);
    void CallObjectProperty(const char *name, std::shared_ptr<AppExecFwk::ETSNativeReference> ability);
    void CallObjectProperty(const char *name, std::shared_ptr<AppExecFwk::ETSNativeReference> ability,
        std::shared_ptr<AppExecFwk::ETSNativeReference> windowStage);
    void CallObjectPropertyCommon(ani_env *env, const char *name, ani_ref ability, ani_ref windowStage);

private:
    static int32_t serialNumber_;
    ani_vm *vm_ = nullptr;
    std::map<int32_t, ani_ref> callbacks_;
    std::mutex mutex_;
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_CONTEXT_ETS_ABILITY_LIFECYCLE_CALLBACK_H