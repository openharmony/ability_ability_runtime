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

#include "sts_ability_delegator_registry.h"

#include <memory>
#include "ability_delegator.h"
#include "ability_delegator_registry.h"
#include "sts_ability_delegator_utils.h"
#include "hilog_tag_wrapper.h"
#include "sts_ability_delegator.h"

namespace OHOS {
namespace AbilityDelegatorSts {
thread_local std::unique_ptr<AbilityRuntime::STSNativeReference> stsReference;

static ani_object GetAbilityDelegator(ani_env *env, [[maybe_unused]]ani_class aniClass)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null env");
        return {};
    }

    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    if (delegator == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        return {};
    }

    if (stsReference == nullptr) {
        ani_object value = CreateStsAbilityDelegator(env);
        stsReference = std::make_unique<AbilityRuntime::STSNativeReference>();
        stsReference->aniObj = value;
        return value;
    } else {
        return stsReference->aniObj;
    }
}

static ani_object GetArguments(ani_env *env, [[maybe_unused]]ani_class aniClass)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null env");
        return {};
    }

    auto abilityDelegatorArgs = AppExecFwk::AbilityDelegatorRegistry::GetArguments();
    if (abilityDelegatorArgs == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "get argument failed");
        return {};
    }

    return CreateStsAbilityDelegatorArguments(env, abilityDelegatorArgs);
}

void StsAbilityDelegatorRegistryInit(ani_env *env)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "StsAbilityDelegatorRegistryInit call");
    ani_status status = ANI_ERROR;
    if (env->ResetError() != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "ResetError failed");
    }

    ani_namespace ns;
    status = env->FindNamespace("L@ohos/app/ability/abilityDelegatorRegistry/abilityDelegatorRegistry;", &ns);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "FindNamespace abilityDelegatorRegistry failed status : %{public}d", status);
        return;
    }

    std::array kitFunctions = {
        ani_native_function {"getAbilityDelegator", nullptr, reinterpret_cast<void *>(GetAbilityDelegator)},
        ani_native_function {"getArguments", nullptr, reinterpret_cast<void *>(GetArguments)},
    };

    status = env->Namespace_BindNativeFunctions(ns, kitFunctions.data(), kitFunctions.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Namespace_BindNativeFunctions failed status : %{public}d", status);
    }

    if (env->ResetError() != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "ResetError failed");
    }

    TAG_LOGI(AAFwkTag::DELEGATOR, "StsAbilityDelegatorRegistryInit end");
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "ANI_Constructor");
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::DELEGATOR, "GetEnv failed status : %{public}d", status);
        return ANI_NOT_FOUND;
    }

    StsAbilityDelegatorRegistryInit(env);
    *result = ANI_VERSION_1;
    TAG_LOGI(AAFwkTag::DELEGATOR, "ANI_Constructor finish");
    return ANI_OK;
}
}
} // namespace AbilityDelegatorSts
} // namespace OHOS
