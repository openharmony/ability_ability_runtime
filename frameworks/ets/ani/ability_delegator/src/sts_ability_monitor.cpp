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
#include "ability_delegator_registry.h"
#include "sts_ability_monitor.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityDelegatorSts {
using namespace OHOS::AbilityRuntime;
STSAbilityMonitor::STSAbilityMonitor(const std::string &abilityName)
    : IAbilityMonitor(abilityName), abilityName_(abilityName)
{}

STSAbilityMonitor::STSAbilityMonitor(const std::string &abilityName, const std::string &moduleName)
    : IAbilityMonitor(abilityName), abilityName_(abilityName), moduleName_(moduleName)
{}

void STSAbilityMonitor::OnSTSAbilityStart(const std::weak_ptr<STSNativeReference> &abilityObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called OnAbilityCreate");
    CallLifecycleCBFunction("onAbilityCreate", abilityObj);
}

void STSAbilityMonitor::OnSTSAbilityForeground(const std::weak_ptr<STSNativeReference> &abilityObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called OnAbilityForeground");
    CallLifecycleCBFunction("onAbilityForeground", abilityObj);
}

void STSAbilityMonitor::OnSTSAbilityBackground(const std::weak_ptr<STSNativeReference> &abilityObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called OnAbilityBackground");
    CallLifecycleCBFunction("onAbilityBackground", abilityObj);
}

void STSAbilityMonitor::OnSTSAbilityDestroy(const std::weak_ptr<STSNativeReference> &abilityObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called OnAbilityDestroy");
    CallLifecycleCBFunction("onAbilityDestroy", abilityObj);
}

void STSAbilityMonitor::OnSTSWindowStageCreate(const std::weak_ptr<STSNativeReference> &abilityObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called OnWindowStageCreate");
    CallLifecycleCBFunction("onWindowStageCreate", abilityObj);
}

void STSAbilityMonitor::OnSTSWindowStageRestore(const std::weak_ptr<STSNativeReference> &abilityObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called OnWindowStageRestore");
    CallLifecycleCBFunction("onWindowStageRestore", abilityObj);
}

void STSAbilityMonitor::OnSTSWindowStageDestroy(const std::weak_ptr<STSNativeReference> &abilityObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called OnWindowStageDestroy");
    CallLifecycleCBFunction("onWindowStageDestroy", abilityObj);
}

void STSAbilityMonitor::SetSTSAbilityMonitor(ani_env *env, ani_object &abilityMonitorObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called SetStsAbilityMonitor");

    stsAbilityMonitor_ = std::make_unique<STSNativeReference>();
    ani_ref objRef = nullptr;
    if (env->GlobalReference_Create(abilityMonitorObj, &objRef) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "GlobalReference_Create failed");
        return;
    }

    ani_vm *aniVM = nullptr;
    if (env->GetVM(&aniVM) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "GetVM failed");
        return;
    }
    vm_ = aniVM;
    stsAbilityMonitor_->aniObj = abilityMonitorObj;
    stsAbilityMonitor_->aniRef = objRef;
}

void STSAbilityMonitor::CallLifecycleCBFunction(const std::string &functionName,
    const std::weak_ptr<AbilityRuntime::STSNativeReference> &abilityObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "CallLifecycleCBFunction, name: %{public}s start", functionName.c_str());
    if (functionName.empty()) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "empty funcName");
        return;
    }

    if (abilityObj.expired()) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null stsAbilityMonitor");
        return;
    }

    ani_env *env = GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null env");
        return;
    }

    ani_status status = ANI_OK;
    ani_object monitorObj = reinterpret_cast<ani_object>(stsAbilityMonitor_->aniRef);
    ani_ref funRef;
    status = env->Object_GetPropertyByName_Ref(monitorObj, functionName.c_str(), &funRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_GetField_Ref failed");
        return;
    }

    ani_fn_object onFn = reinterpret_cast<ani_fn_object>(funRef);
    ani_ref resutlt;
    std::vector<ani_ref> argv = { abilityObj.lock()->aniRef };
    if ((status = env->FunctionalObject_Call(onFn, 1, argv.data(), &resutlt)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "FunctionalObject_Call failed, status : %{public}d", status);
        return;
    }
}

ani_env* STSAbilityMonitor::GetAniEnv()
{
    if (vm_ == nullptr) {
        return nullptr;
    }
    ani_env* aniEnv = nullptr;
    if (vm_->GetEnv(ANI_VERSION_1, &aniEnv) != ANI_OK) {
        return nullptr;
    }
    return aniEnv;
}
}  // namespace AbilityDelegatorJs
}  // namespace OHOS
