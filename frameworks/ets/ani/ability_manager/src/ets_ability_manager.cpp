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

#include "ets_ability_manager.h"

#include "ability_business_error.h"
#include "ability_manager_interface.h"
#include "ani_common_ability_state_data.h"
#include "ets_error_utils.h"
#include "hilog_tag_wrapper.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace EtsAbilityManager {
sptr<AppExecFwk::IAbilityManager> GetAbilityManagerInstance()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> abilityManagerObj =
        systemAbilityManager->GetSystemAbility(ABILITY_MGR_SERVICE_ID);
    return iface_cast<AppExecFwk::IAbilityManager>(abilityManagerObj);
}

static ani_object GetForegroundUIAbilities(ani_env *env)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "call GetForegroundUIAbilities");

    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null env");
        return nullptr;
    }

    sptr<AppExecFwk::IAbilityManager> abilityManager = GetAbilityManagerInstance();
    if (abilityManager == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "abilityManager is null");
        AbilityRuntime::EtsErrorUtil::EtsErrorUtil::ThrowErrorByNativeErr(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER));
        return nullptr;
    }
    std::vector<AppExecFwk::AbilityStateData> list;
    int32_t ret = abilityManager->GetForegroundUIAbilities(list);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "failed: ret=%{public}d", ret);
        AbilityRuntime::AbilityErrorCode code = AbilityRuntime::GetJsErrorCodeByNativeError(ret);
        AbilityRuntime::EtsErrorUtil::EtsErrorUtil::ThrowErrorByNativeErr(env, static_cast<int32_t>(code));
        return nullptr;
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR, "GetForegroundUIAbilities succeeds, list.size=%{public}zu", list.size());
    ani_object aniArray = AppExecFwk::CreateAniAbilityStateDataArray(env, list);
    if (aniArray == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null aniArray");
        AbilityRuntime::EtsErrorUtil::EtsErrorUtil::ThrowErrorByNativeErr(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER));
        return nullptr;
    }
    return aniArray;
}

void StsAbilityManagerRegistryInit(ani_env *env)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "call StsAbilityManagerRegistryInit");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null env");
        return;
    }

    ani_status status = ANI_ERROR;
    if (env->ResetError() != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ResetError failed");
    }

    ani_namespace ns;
    status = env->FindNamespace("L@ohos/app/ability/abilityManager/abilityManager;", &ns);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "FindNamespace abilityManager failed status : %{public}d", status);
        return;
    }

    std::array methods = {
        ani_native_function {
            "nativeGetForegroundUIAbilities",
            ":Lescompat/Array;",
            reinterpret_cast<void *>(GetForegroundUIAbilities)
        },
    };

    status = env->Namespace_BindNativeFunctions(ns, methods.data(), methods.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Namespace_BindNativeFunctions failed status : %{public}d", status);
    }

    if (env->ResetError() != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ResetError failed");
    }
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "in EtsAbilityManager.ANI_Constructor");
    if (vm == nullptr || result == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null vm or result");
        return ANI_INVALID_ARGS;
    }

    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "GetEnv failed, status=%{public}d", status);
        return ANI_NOT_FOUND;
    }

    StsAbilityManagerRegistryInit(env);
    *result = ANI_VERSION_1;
    TAG_LOGI(AAFwkTag::ABILITYMGR, "EtsAbilityManager.ANI_Constructor finished");
    return ANI_OK;
}
}
} // namespace EtsAbilityManager
} // namespace OHOS