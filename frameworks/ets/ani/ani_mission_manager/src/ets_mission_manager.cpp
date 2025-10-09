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
#include "ani_common_start_options.h"
#include "ani_common_util.h"
#include "ani_common_want.h"
#include "ets_error_utils.h"
#include "ets_mission_info_utils.h"
#include "ets_mission_listener.h"
#include "hilog_tag_wrapper.h"
#include "mission_snapshot.h"
#include "permission_constants.h"
#include "start_options.h"
#ifdef SUPPORT_GRAPHICS
#include "pixel_map_taihe_ani.h"
#endif

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
using AbilityManagerClient = AAFwk::AbilityManagerClient;
namespace {
constexpr const char* ETS_MISSION_INFO_NAME = "application.MissionInfo.MissionInfoInner";
constexpr const char* ETS_MISSION_MANAGER_NAME = "@ohos.app.ability.missionManager.missionManager";
constexpr const char* ON_OFF_TYPE = "mission";
constexpr const char* ON_OFF_TYPE_SYNC = "missionEvent";
}
class EtsMissionManager {
public:
    EtsMissionManager(const EtsMissionManager&) = delete;
    EtsMissionManager& operator=(const EtsMissionManager&) = delete;

    static EtsMissionManager& GetInstance()
    {
        return instance;
    }

    static void ClearAllMissions(ani_env *env, ani_object callback)
    {
        instance.OnClearAllMissions(env, callback);
    }

    static void GetMissionInfo(ani_env *env, ani_string deviceId, ani_int missionId, ani_object callback)
    {
        instance.OnGetMissionInfo(env, deviceId, missionId, callback);
    }

     static void GetMissionInfos(ani_env *env, ani_string deviceId, ani_int numMax, ani_object callback)
    {
        instance.OnGetMissionInfos(env, deviceId, numMax, callback);
    }

    static void ClearMission(ani_env *env, ani_int missionId, ani_object callback)
    {
        instance.OnClearMission(env, missionId, callback);
    }

    static void LockMission(ani_env *env, ani_int missionId, ani_object callback)
    {
        instance.OnLockMission(env, missionId, callback);
    }

    static void UnlockMission(ani_env *env, ani_int missionId, ani_object callback)
    {
        instance.OnUnlockMission(env, missionId, callback);
    }

    static void GetMissionSnapShot(ani_env *env, ani_string deviceId, ani_int missionId, ani_object callback)
    {
        instance.OnGetMissionSnapShot(env, deviceId, missionId, callback, false);
    }

    static void GetLowResolutionMissionSnapShot(ani_env *env,
        ani_string deviceId, ani_int missionId, ani_object callback)
    {
        instance.OnGetMissionSnapShot(env, deviceId, missionId, callback, true);
    }

    static void ArrayLengthCheck(ani_env *env, ani_object missionIds)
    {
        instance.OnArrayLengthCheck(env, missionIds);
    }

    static void MoveMissionsToBackground(ani_env *env, ani_object missionIds, ani_object callback)
    {
        instance.OnMoveMissionsToBackground(env, missionIds, callback);
    }

    static void MoveMissionsToForeground(ani_env *env, ani_object missionIds, ani_int topMission, ani_object callback)
    {
        instance.OnMoveMissionsToForeground(env, missionIds, topMission, callback);
    }

    static void MoveMissionToFront(ani_env *env, ani_int missionId, ani_object callback)
    {
        instance.OnMoveMissionToFront(env, missionId, nullptr, callback);
    }

    static void MoveMissionToFrontWithOptions(ani_env *env, ani_int missionId, ani_object options, ani_object callback)
    {
        instance.OnMoveMissionToFront(env, missionId, options, callback);
    }

    static ani_long On(ani_env *env, ani_string type, ani_object listener)
    {
        return instance.OnOn(env, type, listener);
    }

    static void Off(ani_env *env, ani_string type, ani_long listenerId, ani_object callback)
    {
        instance.OnOff(env, type, listenerId, callback);
    }

private:
    EtsMissionManager() = default;
    ~EtsMissionManager() = default;

    static EtsMissionManager instance;

    void OnClearAllMissions(ani_env *env, ani_object callback)
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

    void OnGetMissionInfo(ani_env *env, ani_string deviceId, ani_int missionId, ani_object callback)
    {
        TAG_LOGD(AAFwkTag::MISSION, "OnGetMissionInfo Call");
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::MISSION, "null env");
            return;
        }
        auto emptyObject = GetEmptyMissionInfo(env);
        std::string stdDeviceId = "";
        if (!GetStdString(env, deviceId, stdDeviceId)) {
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

    ani_object GetEmptyMissionInfo(ani_env *env)
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
        status = env->Class_FindMethod(cls, "<ctor>", ":", &method);
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

    void OnGetMissionInfos(ani_env *env, ani_string deviceId, ani_int numMax, ani_object callback)
    {
        TAG_LOGD(AAFwkTag::MISSION, "OnGetMissionInfos Call");
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::MISSION, "null env");
            return;
        }
        std::string stdDeviceId = "";
        if (!GetStdString(env, deviceId, stdDeviceId)) {
            TAG_LOGE(AAFwkTag::MISSION, "GetStdString failed");
            AsyncCallback(env, callback, EtsErrorUtil::CreateInvalidParamError(env,
                "Parse param deviceId failed, must be a string."), nullptr);
            return;
        }
        std::vector<AAFwk::MissionInfo> missionInfos;
        auto ret = AbilityManagerClient::GetInstance()->GetMissionInfos(stdDeviceId,
            numMax, missionInfos);
        if (ret != 0) {
            TAG_LOGE(AAFwkTag::MISSION, "GetMissionInfos is failed. ret = %{public}d.", ret);
            AsyncCallback(env, callback, EtsErrorUtil::CreateErrorByNativeErr(env,
                ret, PermissionConstants::PERMISSION_MANAGE_MISSION), nullptr);
            return;
        }
        auto aniMissionInfos = CreateEtsMissionInfos(env, missionInfos);
        AsyncCallback(env, callback, EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK), aniMissionInfos);
    }

    void OnClearMission(ani_env *env, ani_int missionId, ani_object callback)
    {
        TAG_LOGD(AAFwkTag::MISSION, "OnClearMission Call");
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::MISSION, "null env");
            return;
        }

        auto ret = AbilityManagerClient::GetInstance()->CleanMission(missionId);
        if (ret != 0) {
            TAG_LOGE(AAFwkTag::MISSION, "OnClearMission is failed. ret = %{public}d.", ret);
            AsyncCallback(env, callback, EtsErrorUtil::CreateErrorByNativeErr(env,
                ret, PermissionConstants::PERMISSION_MANAGE_MISSION), nullptr);
            return;
        }

        AsyncCallback(env, callback, EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK), nullptr);
    }
    
    void OnLockMission(ani_env *env, ani_int missionId, ani_object callback)
    {
        TAG_LOGD(AAFwkTag::MISSION, "OnLockMission Call");
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::MISSION, "null env");
            return;
        }
        auto ret = AbilityManagerClient::GetInstance()->LockMissionForCleanup(missionId);
        if (ret != 0) {
            TAG_LOGE(AAFwkTag::MISSION, "OnLockMission is failed. ret = %{public}d.", ret);
            AsyncCallback(env, callback, EtsErrorUtil::CreateErrorByNativeErr(env,
                ret, PermissionConstants::PERMISSION_MANAGE_MISSION), nullptr);
            return;
        }

        AsyncCallback(env, callback, EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK), nullptr);
    }

    void OnUnlockMission(ani_env *env, ani_int missionId, ani_object callback)
    {
        TAG_LOGD(AAFwkTag::MISSION, "OnUnlockMission Call");
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::MISSION, "null env");
            return;
        }

        auto ret = AbilityManagerClient::GetInstance()->UnlockMissionForCleanup(missionId);
        if (ret != 0) {
            TAG_LOGE(AAFwkTag::MISSION, "OnUnlockMission is failed. ret = %{public}d.", ret);
            AsyncCallback(env, callback, EtsErrorUtil::CreateErrorByNativeErr(env,
                ret, PermissionConstants::PERMISSION_MANAGE_MISSION), nullptr);
            return;
        }

        AsyncCallback(env, callback, EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK), nullptr);
    }

    void OnGetMissionSnapShot(ani_env *env,
        ani_string deviceId, ani_int missionId, ani_object callback, bool isLowResolution)
    {
        TAG_LOGD(AAFwkTag::MISSION, "OnGetMissionSnapShot Call");
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::MISSION, "null env");
            return;
        }

        auto emptyObject = GetEmptyMissionSnapShot(env);

        std::string stdDeviceId = "";
        if (!GetStdString(env, deviceId, stdDeviceId)) {
            TAG_LOGE(AAFwkTag::MISSION, "GetStdString failed");
            AsyncCallback(env, callback, EtsErrorUtil::CreateInvalidParamError(env,
                "Parse param deviceId failed, must be a string."), emptyObject);
            return;
        }
        AAFwk::MissionSnapshot missionSnapShot;
        auto ret = AbilityManagerClient::GetInstance()->GetMissionSnapshot(stdDeviceId,
            missionId, missionSnapShot, isLowResolution);
        if (ret != 0) {
            TAG_LOGE(AAFwkTag::MISSION, "OnGetMissionSnapShot is failed. ret = %{public}d.", ret);
            AsyncCallback(env, callback, EtsErrorUtil::CreateErrorByNativeErr(env,
                ret, PermissionConstants::PERMISSION_MANAGE_MISSION), emptyObject);
            return;
        }
        auto aniMissionSnapShot = CreateEtsMissionSnapShot(env, missionSnapShot);
        AsyncCallback(env, callback, EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK), aniMissionSnapShot);
    }
    
    ani_object CreateEtsMissionSnapShot(ani_env *env, const AAFwk::MissionSnapshot &missionSnapShot)
    {
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::MISSION, "env is null");
            return nullptr;
        }
        ani_class cls = nullptr;
        ani_status status = ANI_ERROR;
        status = env->FindClass("application.MissionSnapshot.MissionSnapshotImpl", &cls);
        if (status != ANI_OK || cls == nullptr) {
            TAG_LOGE(AAFwkTag::MISSION, "FindClass failed status = %{public}d", status);
            return nullptr;
        }
        ani_method method = nullptr;
        status = env->Class_FindMethod(cls, "<ctor>", ":", &method);
        if (status != ANI_OK || method == nullptr) {
            TAG_LOGE(AAFwkTag::MISSION, "Class_FindMethod failed status = %{public}d", status);
            return nullptr;
        }
        ani_object object = nullptr;
        status = env->Object_New(cls, method, &object);
        if (status != ANI_OK || object == nullptr) {
            TAG_LOGE(AAFwkTag::MISSION, "Object_New failed status = %{public}d", status);
            return nullptr;
        }
        ani_object abilityObj = WrapElementName(env, missionSnapShot.topAbility);
        if (!SetRefProperty(env, object, "ability", abilityObj)) {
            TAG_LOGE(AAFwkTag::MISSION, "Set ability failed");
            return nullptr;
        }
#ifdef SUPPORT_SCREEN
        auto snapshotValue =
            OHOS::Media::PixelMapTaiheAni::CreateEtsPixelMap(env, missionSnapShot.snapshot);
        if (!SetRefProperty(env, object, "snapshot", snapshotValue)) {
            TAG_LOGE(AAFwkTag::MISSION, "Set snapshot failed");
            return nullptr;
        }
#endif
        return object;
    }

    ani_object GetEmptyMissionSnapShot(ani_env *env)
    {
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::MISSION, "null env");
            return nullptr;
        }
        ani_class cls = nullptr;
        ani_status status = env->FindClass("application.MissionSnapshot.MissionSnapshotImpl", &cls);
        if (status != ANI_OK || cls == nullptr) {
            TAG_LOGE(AAFwkTag::MISSION, "find class failed status: %{public}d", status);
            return nullptr;
        }
        ani_method method = nullptr;
        status = env->Class_FindMethod(cls, "<ctor>", ":", &method);
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

    void OnArrayLengthCheck(ani_env *env, ani_object missionIds)
    {
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::MISSION, "null env");
            return;
        }
        std::vector<int32_t> missionIdList;
        ani_size arrayLen = 0;
        ani_status status = env->Array_GetLength(reinterpret_cast<ani_array>(missionIds), &arrayLen);
        if (status != ANI_OK || arrayLen == 0) {
            TAG_LOGE(AAFwkTag::MISSION, "missionIds is not a valid array or empty");
            EtsErrorUtil::ThrowInvalidParamError(
                env, "Parse param missionIds failed, the size of missionIds must above zero.");
            return;
        }
    }
    void OnMoveMissionsToBackground(ani_env *env, ani_object missionIds, ani_object callback)
    {
        TAG_LOGD(AAFwkTag::MISSION, "OnMoveMissionsToBackground Call");
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::MISSION, "null env");
            return;
        }
        std::vector<int32_t> missionIdList;
        ani_size arrayLen = 0;
        ani_status status = env->Array_GetLength(reinterpret_cast<ani_array>(missionIds), &arrayLen);
        if (status != ANI_OK || arrayLen == 0) {
            TAG_LOGE(AAFwkTag::MISSION, "missionIds is not a valid array or empty");
            AsyncCallback(env, callback,
                EtsErrorUtil::CreateInvalidParamError(
                    env, "Parse param missionIds failed, must be Array<int> and not empty."), nullptr);
            return;
        }
        ani_ref ref = nullptr;
        for (ani_size i = 0; i < arrayLen; ++i) {
            status = env->Array_Get(reinterpret_cast<ani_array>(missionIds), i, &ref);
            if (status != ANI_OK || ref == nullptr) {
                TAG_LOGE(AAFwkTag::MISSION, "Array_GetElement failed at index %{public}zu", i);
                AsyncCallback(env, callback,
                    EtsErrorUtil::CreateInvalidParamError(env, "Parse param missionIds failed, element is invalid."),
                    nullptr);
                return;
            }
            int32_t missionId = 0;
            status = env->Object_CallMethodByName_Int(
                reinterpret_cast<ani_object>(ref), "intValue", nullptr, &missionId);
            if (status != ANI_OK) {
                TAG_LOGE(AAFwkTag::MISSION, "ConvertAniInt failed at index %{public}d", i);
                AsyncCallback(env, callback,
                    EtsErrorUtil::CreateInvalidParamError(env, "Parse param missionIds failed, element must be int."),
                    nullptr);
                return;
            }
            missionIdList.push_back(missionId);
        }
        std::vector<int32_t> resultMissionIds;
        auto ret = AbilityManagerClient::GetInstance()->MoveMissionsToBackground(missionIdList, resultMissionIds);
        if (ret == 0) {
            ani_object arrayValue = CreateIntAniArray(env, resultMissionIds);
            AsyncCallback(env, callback, EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK), arrayValue);
        } else {
            AsyncCallback(env, callback,
                EtsErrorUtil::CreateErrorByNativeErr(env, ret, PermissionConstants::PERMISSION_MANAGE_MISSION),
                nullptr);
        }
    }

    void OnMoveMissionsToForeground(ani_env *env, ani_object missionIds, ani_int topMission, ani_object callback)
    {
        TAG_LOGD(AAFwkTag::MISSION, "OnMoveMissionsToForeground Call");
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::MISSION, "null env");
            return;
        }
        std::vector<int32_t> missionIdList;
        ani_size arrayLen = 0;
        ani_status status = env->Array_GetLength(reinterpret_cast<ani_array>(missionIds), &arrayLen);
        if (status != ANI_OK || arrayLen == 0) {
            TAG_LOGE(AAFwkTag::MISSION, "missionIds is not a valid array or empty");
            AsyncCallback(env, callback,
                EtsErrorUtil::CreateInvalidParamError(env,
                    "Parse param missionIds failed, must be Array<int> and not empty."), nullptr);
            return;
        }
        ani_ref ref = nullptr;
        for (ani_size i = 0; i < arrayLen; ++i) {
            status = env->Array_Get(reinterpret_cast<ani_array>(missionIds), i, &ref);
            if (status != ANI_OK || ref == nullptr) {
                TAG_LOGE(AAFwkTag::MISSION, "Array_GetElement failed at index %{public}zu", i);
                AsyncCallback(env, callback,
                    EtsErrorUtil::CreateInvalidParamError(env, "Parse param missionIds failed, element is invalid."),
                    nullptr);
                return;
            }
            int32_t missionId = 0;
            status = env->Object_CallMethodByName_Int(
                reinterpret_cast<ani_object>(ref), "intValue", nullptr, &missionId);
            if (status != ANI_OK) {
                TAG_LOGE(AAFwkTag::MISSION, "ConvertAniInt failed at index %{public}d", i);
                AsyncCallback(env, callback,
                    EtsErrorUtil::CreateInvalidParamError(env, "Parse param missionIds failed, element must be int."),
                    nullptr);
                return;
            }
            missionIdList.push_back(missionId);
        }

        auto ret = AbilityManagerClient::GetInstance()->MoveMissionsToForeground(missionIdList, topMission);
        if (ret == 0) {
            AsyncCallback(env, callback,
                EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK), nullptr);
        } else {
            AsyncCallback(env, callback,
                EtsErrorUtil::CreateErrorByNativeErr(env, ret, PermissionConstants::PERMISSION_MANAGE_MISSION),
                nullptr);
        }
    }

    void OnMoveMissionToFront(ani_env *env, ani_int missionId, ani_object options, ani_object callback)
    {
        TAG_LOGD(AAFwkTag::MISSION, "OnMoveMissionToFront Call");
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::MISSION, "null env");
            return;
        }
        AAFwk::StartOptions startOptions;
        if (options != nullptr) {
            AppExecFwk::UnwrapStartOptions(env, options, startOptions);
        }
        auto ret = (options == nullptr) ? AbilityManagerClient::GetInstance()->MoveMissionToFront(missionId) :
            AbilityManagerClient::GetInstance()->MoveMissionToFront(missionId, startOptions);
        if (ret == 0) {
            AsyncCallback(env, callback,
                EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK), nullptr);
        } else {
            AsyncCallback(env, callback,
                EtsErrorUtil::CreateErrorByNativeErr(env, ret, PermissionConstants::PERMISSION_MANAGE_MISSION),
                nullptr);
        }
    }

    ani_long OnOn(ani_env *env, ani_string type, ani_object listener)
    {
        TAG_LOGD(AAFwkTag::MISSION, "OnOn Call");
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::MISSION, "null env");
            return ANI_ERROR;
        }
        std::string stdType = "";
        if (!GetStdString(env, type, stdType) || stdType.empty()) {
            TAG_LOGE(AAFwkTag::MISSION, "GetStdString failed");
            EtsErrorUtil::ThrowInvalidParamError(env, "Parse param type failed.");
            return ANI_ERROR;
        }
        if (stdType == ON_OFF_TYPE_SYNC) {
            return OnOnNew(env, type, listener);
        }
        return OnOnOld(env, type, listener);
    }

    ani_long OnOnOld(ani_env *env, ani_string type, ani_object listener)
    {
        TAG_LOGD(AAFwkTag::MISSION, "OnOnOld called");
        std::string stdType = "";
        if (!GetStdString(env, type, stdType) || stdType.empty() || stdType != ON_OFF_TYPE) {
            TAG_LOGE(AAFwkTag::MISSION, "GetStdString failed");
            AbilityRuntime::EtsErrorUtil::ThrowInvalidParamError(
                env, "Parse param type failed, must be a string, value must be mission.");
            return ANI_ERROR;
        }
        missionListenerId_++;
        if (missionListener_ != nullptr) {
            missionListener_->AddEtsListenerObject(env, missionListenerId_, listener);
            return missionListenerId_;
        }
        ani_vm *vm = nullptr;
        if (env->GetVM(&vm) != ANI_OK) {
            TAG_LOGE(AAFwkTag::AUTOFILLMGR, "get vm failed");
            EtsErrorUtil::ThrowInvalidParamError(env, "get vm failed.");
            return ANI_ERROR;
        }
        missionListener_ = new EtsMissionListener(vm);
        auto ret = AbilityManagerClient::GetInstance()->RegisterMissionListener(missionListener_);
        if (ret == 0) {
            missionListener_->AddEtsListenerObject(env, missionListenerId_, listener);
            return missionListenerId_;
        } else {
            TAG_LOGE(AAFwkTag::MISSION, "RegisterMissionListener failed, ret:%{public}d", ret);
            missionListener_ = nullptr;
            if (ret == CHECK_PERMISSION_FAILED) {
                EtsErrorUtil::ThrowNoPermissionError(env, PermissionConstants::PERMISSION_MANAGE_MISSION);
            } else {
                EtsErrorUtil::ThrowError(env, EtsErrorUtil::CreateErrorByNativeErr(env, ret));
            }
            return ANI_ERROR;
        }
    }

    ani_long OnOnNew(ani_env *env, ani_string type, ani_object listener)
    {
        TAG_LOGD(AAFwkTag::MISSION, "OnOnNew called");
        missionListenerId_++;
        if (missionListener_ != nullptr) {
            missionListener_->AddEtsListenerObject(env, missionListenerId_, listener);
            return missionListenerId_;
        }
        ani_vm *vm = nullptr;
        if (env->GetVM(&vm) != ANI_OK) {
            TAG_LOGE(AAFwkTag::AUTOFILLMGR, "get vm failed");
            AbilityRuntime::EtsErrorUtil::ThrowInvalidParamError(env, "get vm failed.");
            return ANI_ERROR;
        }
        missionListener_ = new EtsMissionListener(vm);
        auto ret = AbilityManagerClient::GetInstance()->RegisterMissionListener(missionListener_);
        if (ret == 0) {
            missionListener_->AddEtsListenerObject(env, missionListenerId_, listener, true);
            return missionListenerId_;
        } else {
            TAG_LOGE(AAFwkTag::MISSION, "RegisterMissionListener failed, ret:%{public}d", ret);
            missionListener_ = nullptr;
            if (ret == CHECK_PERMISSION_FAILED) {
                EtsErrorUtil::ThrowNoPermissionError(env, PermissionConstants::PERMISSION_MANAGE_MISSION);
            } else {
                EtsErrorUtil::ThrowError(env, EtsErrorUtil::CreateErrorByNativeErr(env, ret));
            }
            return ANI_ERROR;
        }
    }

    void OnOff(ani_env *env, ani_string type, ani_long listenerId, ani_object callback)
    {
        TAG_LOGD(AAFwkTag::MISSION, "OnOff Call");
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::MISSION, "null env");
            return;
        }
        std::string stdType = "";
        if (!GetStdString(env, type, stdType) || stdType.empty()) {
            TAG_LOGE(AAFwkTag::MISSION, "GetStdString failed");
            EtsErrorUtil::ThrowInvalidParamError(env, "Parse param type failed.");
            return;
        }
        if (stdType == ON_OFF_TYPE_SYNC) {
            return OnOffNew(env, type, listenerId, callback);
        }
        return OnOffOld(env, type, listenerId, callback);
    }

    void OnOffOld(ani_env *env, ani_string type, ani_long listenerId, ani_object callback)
    {
        TAG_LOGD(AAFwkTag::MISSION, "OnOffOld called");
        std::string stdType = "";
        if (!GetStdString(env, type, stdType) || stdType.empty() || stdType != ON_OFF_TYPE) {
            TAG_LOGE(AAFwkTag::MISSION, "GetStdString failed");
            AbilityRuntime::EtsErrorUtil::ThrowInvalidParamError(
                env, "Parse param type failed, must be a string, value must be mission.");
            return;
        }
        if (!missionListener_ || !missionListener_->RemoveEtsListenerObject(listenerId)) {
            AsyncCallback(env,
                callback, EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_CODE_NO_MISSION_LISTENER), nullptr);
            return;
        }
        if (!missionListener_->IsEmpty()) {
            AsyncCallback(env, callback,
                EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK), nullptr);
            return;
        }
        auto ret = AbilityManagerClient::GetInstance()->UnRegisterMissionListener(missionListener_);
        if (ret == 0) {
            AsyncCallback(env, callback,
                EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK), nullptr);
            missionListener_ = nullptr;
        } else {
            AsyncCallback(env, callback,
                EtsErrorUtil::CreateErrorByNativeErr(env, ret, PermissionConstants::PERMISSION_MANAGE_MISSION),
                nullptr);
        }
    }
    void OnOffNew(ani_env *env, ani_string type, ani_long listenerId, ani_object callback)
    {
        TAG_LOGD(AAFwkTag::MISSION, "OnOffNew called");
        if (missionListener_ == nullptr) {
            TAG_LOGE(AAFwkTag::MISSION, "null missionListener_");
            EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
            return;
        }
        if (!missionListener_->RemoveEtsListenerObject(listenerId, true)) {
            TAG_LOGE(AAFwkTag::MISSION, "missionListenerId not found");
            EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_NO_MISSION_LISTENER);
            return;
        }
        if (!missionListener_->IsEmpty()) {
            TAG_LOGD(AAFwkTag::MISSION, "Off success, missionListener not empty");
            return;
        }
        auto ret = AbilityManagerClient::GetInstance()->UnRegisterMissionListener(missionListener_);
        if (ret == 0) {
            TAG_LOGD(AAFwkTag::MISSION, "UnRegisterMissionListener success");
            missionListener_ = nullptr;
        } else {
            TAG_LOGE(AAFwkTag::MISSION, "UnRegisterMissionListener failed");
            if (ret == CHECK_PERMISSION_FAILED) {
                EtsErrorUtil::ThrowNoPermissionError(env, PermissionConstants::PERMISSION_MANAGE_MISSION);
            } else {
                EtsErrorUtil::ThrowError(env, EtsErrorUtil::CreateErrorByNativeErr(env, ret));
            }
            return;
        }
    }
private:
    sptr<EtsMissionListener> missionListener_ = nullptr;
    uint32_t missionListenerId_ = 0;
};

EtsMissionManager EtsMissionManager::instance;

void EtsMissionManagerInit(ani_env *env)
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
            "nativeClearAllMissions", "C{utils.AbilityUtils.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(EtsMissionManager::ClearAllMissions)
        },
        ani_native_function {
            "nativeGetMissionInfo",
            "C{std.core.String}iC{utils.AbilityUtils.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(EtsMissionManager::GetMissionInfo)
        },
        ani_native_function {
            "nativeGetMissionInfos",
            "C{std.core.String}iC{utils.AbilityUtils.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(EtsMissionManager::GetMissionInfos)
        },
        ani_native_function {
            "nativeClearMission", "iC{utils.AbilityUtils.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(EtsMissionManager::ClearMission)
        },
        ani_native_function {
            "nativeLockMission", "iC{utils.AbilityUtils.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(EtsMissionManager::LockMission)
        },
        ani_native_function {
            "nativeUnlockMission", "iC{utils.AbilityUtils.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(EtsMissionManager::UnlockMission)
        },
        ani_native_function {
            "nativeGetMissionSnapShot",
            "C{std.core.String}iC{utils.AbilityUtils.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(EtsMissionManager::GetMissionSnapShot)
        },
        ani_native_function {
            "nativeGetLowResolutionMissionSnapShot",
            "C{std.core.String}iC{utils.AbilityUtils.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(EtsMissionManager::GetLowResolutionMissionSnapShot)
        },
        ani_native_function {
            "nativeArrayLengthCheck",
            "C{escompat.Array}:",
            reinterpret_cast<void *>(EtsMissionManager::ArrayLengthCheck)
        },
        ani_native_function {
            "nativeMoveMissionsToBackground",
            "C{escompat.Array}C{utils.AbilityUtils.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(EtsMissionManager::MoveMissionsToBackground)
        },
        ani_native_function {
            "nativeMoveMissionsToForeground",
            "C{escompat.Array}iC{utils.AbilityUtils.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(EtsMissionManager::MoveMissionsToForeground)
        },
        ani_native_function {
            "nativeMoveMissionToFront",
            "iC{utils.AbilityUtils.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(EtsMissionManager::MoveMissionToFront)
        },
        ani_native_function {
            "nativeMoveMissionToFront",
            "iC{@ohos.app.ability.StartOptions.StartOptions}C{utils.AbilityUtils.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(EtsMissionManager::MoveMissionToFrontWithOptions)
        },
        ani_native_function {
            "nativeOn",
            "C{std.core.String}C{application.MissionListener.MissionListener}:l",
            reinterpret_cast<void *>(EtsMissionManager::On)
        },
        ani_native_function {
            "nativeOff",
            "C{std.core.String}lC{utils.AbilityUtils.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(EtsMissionManager::Off)
        }
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