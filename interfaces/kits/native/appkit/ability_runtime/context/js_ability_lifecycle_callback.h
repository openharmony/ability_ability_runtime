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

#ifndef OHOS_ABILITY_RUNTIME_CONTEXT_JS_ABILITY_LIFECYCLE_CALLBACK_H
#define OHOS_ABILITY_RUNTIME_CONTEXT_JS_ABILITY_LIFECYCLE_CALLBACK_H

#include <map>
#include <memory>

#include "ability_lifecycle_callback.h"

class NativeReference;
typedef struct napi_env__* napi_env;
typedef struct napi_value__* napi_value;

namespace OHOS {
namespace AbilityRuntime {
class JsAbilityLifecycleCallbackArgs : public AbilityLifecycleCallbackArgs {
public:
    explicit JsAbilityLifecycleCallbackArgs(const std::shared_ptr<NativeReference> &ref) : ref_(ref)
    {
        type_ = AbilityLifecycleCallbackType::JS;
    }
    bool IsValid() const override { return ref_ != nullptr; }
    const std::shared_ptr<NativeReference> &ref_;
};

class JsAbilityLifecycleCallback : public AbilityLifecycleCallback,
                                   public std::enable_shared_from_this<JsAbilityLifecycleCallback> {
public:
    explicit JsAbilityLifecycleCallback(napi_env env);
    void OnAbilityCreate(const AbilityLifecycleCallbackArgs &ability) override;
    void OnWindowStageCreate(const AbilityLifecycleCallbackArgs &ability,
        const AbilityLifecycleCallbackArgs &windowStage) override;
    void OnWindowStageDestroy(const AbilityLifecycleCallbackArgs &ability,
        const AbilityLifecycleCallbackArgs &windowStage) override;
    void OnWindowStageActive(const AbilityLifecycleCallbackArgs &ability,
        const AbilityLifecycleCallbackArgs &windowStage) override;
    void OnWindowStageInactive(const AbilityLifecycleCallbackArgs &ability,
        const AbilityLifecycleCallbackArgs &windowStage) override;
    void OnAbilityWillCreate(const AbilityLifecycleCallbackArgs &ability) override;
    void OnWindowStageWillCreate(const AbilityLifecycleCallbackArgs &ability,
        const AbilityLifecycleCallbackArgs &windowStage) override;
    void OnWindowStageWillDestroy(const AbilityLifecycleCallbackArgs &ability,
        const AbilityLifecycleCallbackArgs &windowStage) override;
    void OnAbilityWillDestroy(const AbilityLifecycleCallbackArgs &ability) override;
    void OnAbilityWillForeground(const AbilityLifecycleCallbackArgs &ability) override;
    void OnAbilityWillBackground(const AbilityLifecycleCallbackArgs &ability) override;
    void OnNewWant(const AbilityLifecycleCallbackArgs &ability) override;
    void OnWillNewWant(const AbilityLifecycleCallbackArgs &ability) override;
    void OnAbilityDestroy(const AbilityLifecycleCallbackArgs &ability) override;
    void OnAbilityForeground(const AbilityLifecycleCallbackArgs &ability) override;
    void OnAbilityBackground(const AbilityLifecycleCallbackArgs &ability) override;
    void OnAbilityContinue(const AbilityLifecycleCallbackArgs &ability) override;
    void OnAbilityWillContinue(const AbilityLifecycleCallbackArgs &ability) override;
    void OnWindowStageWillRestore(const AbilityLifecycleCallbackArgs &ability,
        const AbilityLifecycleCallbackArgs &windowStage) override;
    void OnWindowStageRestore(const AbilityLifecycleCallbackArgs &ability,
        const AbilityLifecycleCallbackArgs &windowStage) override;
    void OnAbilityWillSaveState(const AbilityLifecycleCallbackArgs &ability) override;
    void OnAbilitySaveState(const AbilityLifecycleCallbackArgs &ability) override;
    int32_t Register(napi_value jsCallback, bool isSync = false);
    bool UnRegister(int32_t callbackId, bool isSync = false);
    bool IsEmpty() const;
    void OnWillForeground(const AbilityLifecycleCallbackArgs &ability) override;
    void OnDidForeground(const AbilityLifecycleCallbackArgs &ability) override;
    void OnWillBackground(const AbilityLifecycleCallbackArgs &ability) override;
    void OnDidBackground(const AbilityLifecycleCallbackArgs &ability) override;
    static int32_t serialNumber_;

private:
    napi_env env_ = nullptr;
    std::shared_ptr<NativeReference> jsCallback_;
    std::map<int32_t, std::shared_ptr<NativeReference>> callbacks_;
    std::map<int32_t, std::shared_ptr<NativeReference>> callbacksSync_;
    void CallJsMethod(const std::string &methodName, const std::shared_ptr<NativeReference> &ability);
    void CallWindowStageJsMethod(const std::string &methodName, const std::shared_ptr<NativeReference> &ability,
        const std::shared_ptr<NativeReference> &windowStage);
    void CallJsMethodInnerCommon(const std::string &methodName, const std::shared_ptr<NativeReference> &ability,
        const std::shared_ptr<NativeReference> &windowStage,
        const std::map<int32_t, std::shared_ptr<NativeReference>> callbacks);
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_CONTEXT_JS_ABILITY_LIFECYCLE_CALLBACK_H