/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "ets_hyper_snap_manager.h"

#include <unordered_map>

#include "ability_business_error.h"
#include "ets_error_utils.h"
#include "hilog_tag_wrapper.h"
#ifdef RESOURCE_SCHEDULE_SERVICE_ENABLE
#include "res_sched_client.h"
#include "res_type.h"
#endif

namespace OHOS {
namespace HyperSnapManagerEts {
namespace {
constexpr const char *HYPER_SNAP_MANAGER_SPACE_NAME = "@ohos.app.ability.hyperSnapManager.hyperSnapManager";
} // namespace

class EtsHyperSnapManager final {
public:
    static void SetHyperSnapEnabled(ani_env *env, ani_boolean enabledFlag);

    static void RequestRebuildHyperSnap(ani_env *env);
};

void EtsHyperSnapManager::SetHyperSnapEnabled(ani_env *env, ani_boolean enabledFlag)
{
    TAG_LOGD(AAFwkTag::APPKIT, "SetHyperSnapEnabled called");
#ifdef RESOURCE_SCHEDULE_SERVICE_ENABLE
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "env null");
        return;
    }

    bool flag = (enabledFlag != 0);
    std::unordered_map<std::string, std::string> payload {
        { "enableFlag", flag ? "1" : "0" },
    };
    std::unordered_map<std::string, std::string> reply;
    TAG_LOGD(AAFwkTag::APPKIT, "enableFlag is %{public}d", flag);
    uint32_t resType = ResourceSchedule::ResType::RES_TYPE_CTRL_FORKALL_IMAGE_INTERFACE;
    int32_t errCode = ResourceSchedule::ResSchedClient::GetInstance().ReportSyncEvent(resType,
        ResourceSchedule::ResType::CtrlForkallImageInterfaceCode::SET_SUPPORT_MIRROR_PROCESS, payload, reply);
    if (errCode != 0) {
        TAG_LOGE(AAFwkTag::APPKIT, "set enable fail, %{public}d", errCode);
        AbilityRuntime::EtsErrorUtil::ThrowError(env,
            AbilityRuntime::AbilityErrorCode::ERROR_CODE_SEND_REQUEST_TO_SYSTEM_FAIL);
    }
#endif
}

void EtsHyperSnapManager::RequestRebuildHyperSnap(ani_env *env)
{
    TAG_LOGD(AAFwkTag::APPKIT, "RequestRebuildHyperSnap called");
#ifdef RESOURCE_SCHEDULE_SERVICE_ENABLE
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "env null");
        return;
    }

    std::unordered_map<std::string, std::string> payload;
    std::unordered_map<std::string, std::string> reply;
    uint32_t resType = ResourceSchedule::ResType::RES_TYPE_CTRL_FORKALL_IMAGE_INTERFACE;
    int32_t errCode = ResourceSchedule::ResSchedClient::GetInstance().ReportSyncEvent(resType,
        ResourceSchedule::ResType::CtrlForkallImageInterfaceCode::REBUILD_IMAGE, payload, reply);
    if (errCode != 0) {
        TAG_LOGE(AAFwkTag::APPKIT, "rebuild fail, %{public}d", errCode);
        AbilityRuntime::EtsErrorUtil::ThrowError(env,
            AbilityRuntime::AbilityErrorCode::ERROR_CODE_SEND_REQUEST_TO_SYSTEM_FAIL);
    }
#endif
}

void EtsHyperSnapManagerRegisterInit(ani_env *env)
{
    TAG_LOGD(AAFwkTag::APPKIT, "EtsHyperSnapManagerRegisterInit call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "env null ptr");
        return;
    }
    ani_status status = ANI_ERROR;
    if (env->ResetError() != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "ResetError failed");
    }
    ani_namespace ns;
    status = env->FindNamespace(HYPER_SNAP_MANAGER_SPACE_NAME, &ns);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "FindNamespace hyperSnapManager failed status : %{public}d", status);
        return;
    }
    std::array kitFunctions = {
        ani_native_function{
            "nativeSetHyperSnapEnabled", nullptr,
            reinterpret_cast<void *>(EtsHyperSnapManager::SetHyperSnapEnabled)},
        ani_native_function{"nativeRequestRebuildHyperSnap", nullptr,
            reinterpret_cast<void *>(EtsHyperSnapManager::RequestRebuildHyperSnap)},
    };
    status = env->Namespace_BindNativeFunctions(ns, kitFunctions.data(), kitFunctions.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Namespace_BindNativeFunctions failed status : %{public}d", status);
    }
    if (env->ResetError() != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "ResetError failed");
    }
    TAG_LOGD(AAFwkTag::APPKIT, "EtsHyperSnapManagerRegisterInit end");
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGD(AAFwkTag::APPKIT, "in HyperSnapManagerEts.ANI_Constructor");
    if (vm == nullptr || result == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null vm or result");
        return ANI_INVALID_ARGS;
    }

    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "GetEnv failed, status=%{public}d", status);
        return ANI_NOT_FOUND;
    }
    EtsHyperSnapManagerRegisterInit(env);
    *result = ANI_VERSION_1;
    TAG_LOGD(AAFwkTag::APPKIT, "HyperSnapManagerEts.ANI_Constructor finished");
    return ANI_OK;
}
} // extern "C"
} // namespace HyperSnapManagerEts
} // namespace OHOS