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

#include "ets_mission_manager.h"

#include "ability_manager_client.h"
#include "ani.h"
#include "ani_common_util.h"
#include "ets_error_utils.h"
#include "ets_mission_info_utils.h"
#include "hilog_tag_wrapper.h"
#include "permission_constants.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
using AbilityManagerClient = AAFwk::AbilityManagerClient;
namespace {
constexpr const char* ETS_MISSION_INFO_NAME = "Lapplication/MissionInfo/MissionInfoInner;";
constexpr const char* ETS_MISSION_MANAGER_NAME = "L@ohos/app/ability/missionManager/missionManager;";
}
class EtsMissionManager {
public:
    EtsMissionManager(const EtsMissionManager&) = delete;
    EtsMissionManager& operator=(const EtsMissionManager&) = delete;

    static EtsMissionManager& GetInstance()
    {
        return instance;
    }

    static void ClearAllMissions(ani_env* env, ani_object callback)
    {
        instance.OnClearAllMissions(env, callback);
    }

    static void GetMissionInfo(ani_env* env, ani_string deviceId, ani_int missionId, ani_object callback)
    {
        instance.OnGetMissionInfo(env, deviceId, missionId, callback);
    }
private:
    EtsMissionManager() = default;
    ~EtsMissionManager() = default;

    static EtsMissionManager instance;

    void OnClearAllMissions(ani_env* env, ani_object callback)
    {
        TAG_LOGD(AAFwkTag::MISSION, "OnClearAllMissions Call");
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::MISSION, "null env");
            return;
        }
        auto ret = AbilityManagerClient::GetInstance()->CleanAllMissions();
        if (ret != 0) {
            TAG_LOGE(AAFwkTag::MISSION, "OnClearAllMissions is failed. ret = %{public}d.", ret);
            AsyncCallback(env, callback, EtsErrorUtil::CreateErrorByNativeErr(env,
                ret, PermissionConstants::PERMISSION_MANAGE_MISSION), nullptr);
            return;
        }
        AsyncCallback(env, callback, EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK), nullptr);
    }

    void OnGetMissionInfo(ani_env* env, ani_string deviceId, ani_int missionId, ani_object callback)
    {
        TAG_LOGD(AAFwkTag::MISSION, "OnGetMissionInfo Call");
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::MISSION, "null env");
            return;
        }
        auto emptyObject = GetEmptyMissionInfo(env);
        std::string stdDeviceId = "";
        if (!GetStdString(env, deviceId, stdDeviceId) || stdDeviceId.empty()) {
            TAG_LOGE(AAFwkTag::MISSION, "GetStdString failed");
            AsyncCallback(env, callback, EtsErrorUtil::CreateInvalidParamError(env,
                "Parse param deviceId failed, must be a string."), emptyObject);
            return;
        }
        AAFwk::MissionInfo missionInfo;
        auto ret = AbilityManagerClient::GetInstance()->GetMissionInfo(stdDeviceId,
            missionId, missionInfo);
        if (ret != 0) {
            TAG_LOGE(AAFwkTag::MISSION, "GetMissionInfo is failed. ret = %{public}d.", ret);
            AsyncCallback(env, callback, EtsErrorUtil::CreateErrorByNativeErr(env,
                ret, PermissionConstants::PERMISSION_MANAGE_MISSION), emptyObject);
            return;
        }
        auto aniMissionInfo = CreateEtsMissionInfo(env, missionInfo);
        AsyncCallback(env, callback, EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK), aniMissionInfo);
    }

    ani_object GetEmptyMissionInfo(ani_env* env)
    {
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::MISSION, "null env");
            return nullptr;
        }
        ani_class cls = nullptr;
        ani_status status = env->FindClass(ETS_MISSION_INFO_NAME, &cls);
        if (status != ANI_OK || cls == nullptr) {
            TAG_LOGE(AAFwkTag::MISSION, "find Context failed status: %{public}d", status);
            return nullptr;
        }
        ani_method method = nullptr;
        status = env->Class_FindMethod(cls, "<ctor>", ":V", &method);
        if (status != ANI_OK || method == nullptr) {
            TAG_LOGE(AAFwkTag::MISSION, "Class_FindMethod ctor failed status: %{public}d", status);
            return nullptr;
        }
        ani_object objValue = nullptr;
        status = env->Object_New(cls, method, &objValue);
        if (status != ANI_OK || objValue == nullptr) {
            TAG_LOGE(AAFwkTag::MISSION, "Object_New failed status: %{public}d", status);
            return nullptr;
        }
        return objValue;
    }
};

EtsMissionManager EtsMissionManager::instance;

void EtsMissionManagerInit(ani_env* env)
{
    TAG_LOGD(AAFwkTag::MISSION, "EtsMissionManagerInit Call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::MISSION, "null env");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_namespace ns;
    status = env->FindNamespace(ETS_MISSION_MANAGER_NAME, &ns);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::MISSION, "FindNamespace application failed status: %{public}d", status);
        return;
    }
    std::array methods = {
        ani_native_function {
            "nativeClearAllMissions", "Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
            reinterpret_cast<void *>(EtsMissionManager::ClearAllMissions)
        },
        ani_native_function {
            "nativeGetMissionInfo",
            "Lstd/core/String;ILutils/AbilityUtils/AsyncCallbackWrapper;:V",
            reinterpret_cast<void *>(EtsMissionManager::GetMissionInfo)
        },
    };
    status = env->Namespace_BindNativeFunctions(ns, methods.data(), methods.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::MISSION, "Namespace_BindNativeFunctions failed status: %{public}d", status);
    }
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGD(AAFwkTag::MISSION, "in MissionManagerETS.ANI_Constructor");
    if (vm == nullptr || result == nullptr) {
        TAG_LOGE(AAFwkTag::MISSION, "null vm or result");
        return ANI_INVALID_ARGS;
    }
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::MISSION, "GetEnv failed, status: %{public}d", status);
        return ANI_NOT_FOUND;
    }
    EtsMissionManagerInit(env);
    *result = ANI_VERSION_1;
    TAG_LOGD(AAFwkTag::MISSION, "MissionManagerETS.ANI_Constructor finished");
    return ANI_OK;
}
}
} // namespace AbilityRuntime
} // namespace OHOS