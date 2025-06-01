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
#include "ets_ability_monitor.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityDelegatorEts {
using namespace OHOS::AbilityRuntime;
EtsAbilityMonitor::EtsAbilityMonitor(const std::string &abilityName)
    : IAbilityMonitor(abilityName), abilityName_(abilityName)
{}

EtsAbilityMonitor::EtsAbilityMonitor(const std::string &abilityName, const std::string &moduleName)
    : IAbilityMonitor(abilityName), abilityName_(abilityName), moduleName_(moduleName)
{}

void EtsAbilityMonitor::OnAbilityStart(const std::weak_ptr<AppExecFwk::BaseDelegatorAbilityProperty> &abilityObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called OnAbilityStart");
    auto runtimeObj = GetRuntimeObject(abilityObj);
    if (!runtimeObj) {
        return;
    }
    CallLifecycleCBFunction("onAbilityCreate", runtimeObj);
}

void EtsAbilityMonitor::OnAbilityForeground(const std::weak_ptr<AppExecFwk::BaseDelegatorAbilityProperty> &abilityObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called OnAbilityForeground");
    auto runtimeObj = GetRuntimeObject(abilityObj);
    if (!runtimeObj) {
        return;
    }
    CallLifecycleCBFunction("onAbilityForeground", runtimeObj);
}

void EtsAbilityMonitor::OnAbilityBackground(const std::weak_ptr<AppExecFwk::BaseDelegatorAbilityProperty> &abilityObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called OnAbilityBackground");
    auto runtimeObj = GetRuntimeObject(abilityObj);
    if (!runtimeObj) {
        return;
    }
    CallLifecycleCBFunction("onAbilityBackground", runtimeObj);
}

void EtsAbilityMonitor::OnAbilityStop(const std::weak_ptr<AppExecFwk::BaseDelegatorAbilityProperty> &abilityObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called OnAbilityStop");
    auto runtimeObj = GetRuntimeObject(abilityObj);
    if (!runtimeObj) {
        return;
    }
    CallLifecycleCBFunction("onAbilityDestroy", runtimeObj);
}

void EtsAbilityMonitor::OnWindowStageCreate(const std::weak_ptr<AppExecFwk::BaseDelegatorAbilityProperty> &abilityObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called OnWindowStageCreate");
    auto runtimeObj = GetRuntimeObject(abilityObj);
    if (!runtimeObj) {
        return;
    }
    CallLifecycleCBFunction("onWindowStageCreate", runtimeObj);
}

void EtsAbilityMonitor::OnWindowStageRestore(const std::weak_ptr<AppExecFwk::BaseDelegatorAbilityProperty> &abilityObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called OnWindowStageRestore");
    auto runtimeObj = GetRuntimeObject(abilityObj);
    if (!runtimeObj) {
        return;
    }
    CallLifecycleCBFunction("onWindowStageRestore", runtimeObj);
}

void EtsAbilityMonitor::OnWindowStageDestroy(const std::weak_ptr<AppExecFwk::BaseDelegatorAbilityProperty> &abilityObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called OnWindowStageDestroy");
    auto runtimeObj = GetRuntimeObject(abilityObj);
    if (!runtimeObj) {
        return;
    }
    CallLifecycleCBFunction("onWindowStageDestroy", runtimeObj);
}

void EtsAbilityMonitor::SetEtsAbilityMonitor(ani_env *env, ani_object &abilityMonitorObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called SetEtsAbilityMonitor");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null env");
        return;
    }
    EtsAbilityMonitor_ = std::make_unique<STSNativeReference>();
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
    if (EtsAbilityMonitor_ == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null EtsAbilityMonitor_");
        return;
    }
    EtsAbilityMonitor_->aniObj = abilityMonitorObj;
    EtsAbilityMonitor_->aniRef = objRef;
}

void EtsAbilityMonitor::CallLifecycleCBFunction(const std::string &functionName,
    const std::shared_ptr<AbilityRuntime::STSNativeReference> &abilityObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "CallLifecycleCBFunction, name: %{public}s start", functionName.c_str());
    if (functionName.empty()) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "empty funcName");
        return;
    }

    if (abilityObj == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null EtsAbilityMonitor");
        return;
    }

    ani_env *env = GetAniEnv();
    if (env == nullptr || EtsAbilityMonitor_ == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null env or EtsAbilityMonitor_");
        return;
    }

    ani_status status = ANI_OK;
    ani_object monitorObj = reinterpret_cast<ani_object>(EtsAbilityMonitor_->aniRef);
    ani_ref funRef;
    status = env->Object_GetPropertyByName_Ref(monitorObj, functionName.c_str(), &funRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_GetField_Ref failed status: %{public}d", status);
        return;
    }

    ani_fn_object onFn = reinterpret_cast<ani_fn_object>(funRef);
    ani_ref resutlt;
    std::vector<ani_ref> argv = { abilityObj->aniRef };
    if ((status = env->FunctionalObject_Call(onFn, 1, argv.data(), &resutlt)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "FunctionalObject_Call failed, status: %{public}d", status);
        return;
    }
}

ani_env* EtsAbilityMonitor::GetAniEnv()
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

std::shared_ptr<AbilityRuntime::STSNativeReference> EtsAbilityMonitor::GetRuntimeObject(
    const std::weak_ptr<AppExecFwk::BaseDelegatorAbilityProperty> &abilityObj)
{
    auto baseProperty = abilityObj.lock();
    if (!baseProperty) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "abilityObj is expired");
        return nullptr;
    }
    auto etsbaseProperty = std::static_pointer_cast<AppExecFwk::ETSDelegatorAbilityProperty>(baseProperty);
    auto runtimeObj = etsbaseProperty->object_.lock();
    if (!runtimeObj) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "runtimeObj is nullptr");
        return nullptr;
    }
    return runtimeObj;
}
}  // namespace AbilityDelegatorJs
}  // namespace OHOS
