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

#include "ability_lifecycle_callback.h"

typedef struct __ani_env ani_env;
typedef struct __ani_vm ani_vm;
typedef class __ani_object *ani_object;
typedef class __ani_ref *ani_ref;

namespace OHOS {
namespace AbilityRuntime {
struct STSNativeReference;

class EtsAbilityLifecycleCallback : public AbilityLifecycleCallback,
                                   public std::enable_shared_from_this<EtsAbilityLifecycleCallback> {
public:
    explicit EtsAbilityLifecycleCallback(ani_env *env);
    void OnAbilityCreate(std::shared_ptr<STSNativeReference> ability) override;
    void OnWindowStageCreate(std::shared_ptr<STSNativeReference> ability,
        std::shared_ptr<STSNativeReference> windowStage) override;
    void OnWindowStageDestroy(std::shared_ptr<STSNativeReference> ability,
        std::shared_ptr<STSNativeReference> windowStage) override;
    void OnAbilityDestroy(std::shared_ptr<STSNativeReference> ability) override;
    void OnAbilityForeground(std::shared_ptr<STSNativeReference> ability) override;
    void OnAbilityBackground(std::shared_ptr<STSNativeReference> ability) override;

    int32_t Register(ani_object callback);
    bool Unregister(int32_t callbackId);
    bool IsEmpty() const;

private:
    ani_env *GetAniEnv();
    void CallObjectMethod(const char *methodName, const char *signature,
        std::shared_ptr<STSNativeReference> ability);
    void CallObjectMethod(const char *methodName, const char *signature,
        std::shared_ptr<STSNativeReference> ability, std::shared_ptr<STSNativeReference> windowStage);

private:
    static int32_t serialNumber_;
    ani_vm *vm_ = nullptr;
    std::map<int32_t, ani_ref> callbacks_;
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_CONTEXT_ETS_ABILITY_LIFECYCLE_CALLBACK_H