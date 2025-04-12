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
STSAbilityMonitor::STSAbilityMonitor(ani_env* env_, const std::string &abilityName) : env_(env_), abilityName_(abilityName)
{}

STSAbilityMonitor::STSAbilityMonitor(ani_env* env_, const std::string &abilityName, const std::string &moduleName)
    : env_(env_), abilityName_(abilityName), moduleName_(moduleName)
{}

void STSAbilityMonitor::OnAbilityCreate(const std::weak_ptr<STSNativeReference> &abilityObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called OnAbilityCreate");
    CallLifecycleCBFunction("onAbilityCreate", abilityObj);
}

void STSAbilityMonitor::OnAbilityForeground(const std::weak_ptr<STSNativeReference> &abilityObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called OnAbilityForeground");
    CallLifecycleCBFunction("onAbilityForeground", abilityObj);
}

void STSAbilityMonitor::OnAbilityBackground(const std::weak_ptr<STSNativeReference> &abilityObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called OnAbilityBackground");
    CallLifecycleCBFunction("onAbilityBackground", abilityObj);
}

void STSAbilityMonitor::OnAbilityDestroy(const std::weak_ptr<STSNativeReference> &abilityObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called OnAbilityDestroy");
    CallLifecycleCBFunction("onAbilityDestroy", abilityObj);
}

void STSAbilityMonitor::OnWindowStageCreate(const std::weak_ptr<STSNativeReference> &abilityObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called OnWindowStageCreate");
    CallLifecycleCBFunction("onWindowStageCreate", abilityObj);
}

void STSAbilityMonitor::OnWindowStageRestore(const std::weak_ptr<STSNativeReference> &abilityObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called OnWindowStageRestore");
    CallLifecycleCBFunction("onWindowStageRestore", abilityObj);
}

void STSAbilityMonitor::OnWindowStageDestroy(const std::weak_ptr<STSNativeReference> &abilityObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called OnWindowStageDestroy");
    CallLifecycleCBFunction("onWindowStageDestroy", abilityObj);
}

void STSAbilityMonitor::SetStsAbilityMonitor(ani_object abilityMonitorObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called SetStsAbilityMonitor");
    stsAbilityMonitor_ = std::unique_ptr<STSNativeReference>();

    ani_ref objRef = nullptr;
    if (env_->GlobalReference_Create(abilityMonitorObj, &objRef) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "GlobalReference_Create failed");
    }
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

    ani_status status = ANI_OK;
    env_->DescribeError();
    env_->ResetError();

    ani_class cls = nullptr;
    if ((status = env_->FindClass("Lapplication/AbilityMonitor/AbilityMonitorInner", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "status : %{public}d", status);
        return;
    }

    ani_method method = nullptr;
    status = env_->Class_FindMethod(cls, "<ctor>", ":V", &method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "call Class_FindMethod ctor failed");
        return;
    }

    ani_object obj = nullptr;
    status = env_->Object_New(cls, method, &obj);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "call Object_New obj failed");
        return;
    }

    method = nullptr;
    if ((status = env_->Class_FindMethod(cls, functionName.c_str(), nullptr, &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindMethod status : %{public}d", status);
        return;
    }

    auto lockedPtr = const_cast<std::weak_ptr<AbilityRuntime::STSNativeReference>&>(abilityObj).lock();

    if (lockedPtr && (status = env_->Object_CallMethod_Void(obj, method, nullptr, lockedPtr->aniObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_CallMethod_Void_V status : %{public}d", status);
    }
    TAG_LOGI(AAFwkTag::DELEGATOR, "CallLifecycleCBFunction, name: %{public}s end", functionName.c_str());
}
}  // namespace AbilityDelegatorJs
}  // namespace OHOS
