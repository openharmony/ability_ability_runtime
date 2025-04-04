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

#ifndef OHOS_ABILITY_RUNTIME_STS_ABILITY_MONITOR_H
#define OHOS_ABILITY_RUNTIME_STS_ABILITY_MONITOR_H

#include <memory>
#include <string>
#include "native_engine/native_reference.h"
#include "sts_runtime.h"

namespace OHOS {
namespace AbilityDelegatorSts {
class STSAbilityMonitor {
public:
    /**
     * A constructor used to create a STSAbilityMonitor instance with the input parameter passed.
     *
     * @param abilityName Indicates the specified ability name for monitoring the lifecycle state changes
     * of the ability.
     */
    explicit STSAbilityMonitor(ani_env* env, const std::string &abilityName);

    /**
     * A constructor used to create a STSAbilityMonitor instance with the input parameter passed.
     *
     * @param abilityName Indicates the specified ability name for monitoring the lifecycle state changes
     * of the ability.
     *
     * @param moduleName Indicates the specified module name for monitoring the lifecycle state changes
     * of the ability.
     */
    explicit STSAbilityMonitor(ani_env* env, const std::string &abilityName, const std::string &moduleName);

    /**
     * Default deconstructor used to deconstruct.
     */
    ~STSAbilityMonitor() = default;

    /**
     * Called when ability is started.
     * Then call the corresponding method on the js side through the saved js object.
     *
     * @param abilityObj Indicates the ability object.
     */
    void OnAbilityCreate(const std::weak_ptr<AbilityRuntime::STSNativeReference> &abilityObj);

    /**
     * Called when ability is in foreground.
     * Then call the corresponding method on the js side through the saved js object.
     *
     * @param abilityObj Indicates the ability object.
     */
    void OnAbilityForeground(const std::weak_ptr<AbilityRuntime::STSNativeReference> &abilityObj);

    /**
     * Called when ability is in background.
     * Then call the corresponding method on the js side through the saved js object.
     *
     * @param abilityObj Indicates the ability object.
     */
    void OnAbilityBackground(const std::weak_ptr<AbilityRuntime::STSNativeReference> &abilityObj);

    /**
     * Called when ability is stopped.
     * Then call the corresponding method on the js side through the saved js object.
     *
     * @param abilityObj Indicates the ability object.
     */
    void OnAbilityDestroy(const std::weak_ptr<AbilityRuntime::STSNativeReference> &abilityObj);

    /**
     * Called when window stage is created.
     * Then call the corresponding method on the js side through the saved js object.
     *
     * @param abilityObj Indicates the ability object.
     */
    void OnWindowStageCreate(const std::weak_ptr<AbilityRuntime::STSNativeReference> &abilityObj);

    /**
     * Called when window stage is restored.
     * Then call the corresponding method on the js side through the saved js object.
     *
     * @param abilityObj Indicates the ability object.
     */
    void OnWindowStageRestore(const std::weak_ptr<AbilityRuntime::STSNativeReference> &abilityObj);

    /**
     * Called when window stage is destroyed.
     * Then call the corresponding method on the js side through the saved js object.
     *
     * @param abilityObj Indicates the ability object.
     */
    void OnWindowStageDestroy(const std::weak_ptr<AbilityRuntime::STSNativeReference> &abilityObj);

    /**
     * Sets the js object.
     *
     * @param jsAbilityMonitor Indicates the js object.
     */
    void SetStsAbilityMonitor(ani_object abilityMonitorObj);

    /**
     * Sets the native env.
     *
     * @param env Indicates the native env.
     */
    void SetJsAbilityMonitorEnv(ani_env* env)
    {
        env_ = env;
    }

    /**
     * Obtains the saved js object.
     *
     * @return the saved js object.
     */
    std::unique_ptr<AbilityRuntime::STSNativeReference> &GetStsAbilityMonitor()
    {
        return stsAbilityMonitor_;
    }

private:
    void CallLifecycleCBFunction(const std::string &functionName,
        const std::weak_ptr<AbilityRuntime::STSNativeReference> &abilityObj);

private:
    ani_env* env_ = nullptr;
    std::string abilityName_ = "";
    std::string moduleName_ = "";
    std::unique_ptr<AbilityRuntime::STSNativeReference> stsAbilityMonitor_ = nullptr;
};
}  // namespace AbilityDelegatorJs
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_STS_ABILITY_MONITOR_H
