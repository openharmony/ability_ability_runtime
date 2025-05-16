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

#include "sts_app_manager.h"
#include "hilog_tag_wrapper.h"
#include "ability_manager_client.h"
#include "ability_manager_interface.h"
#include "app_mgr_constants.h"
#include "app_mgr_interface.h"
#include "ipc_skeleton.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "sts_error_utils.h"
#include "ani_common_util.h"
#include "ani_enum_convert.h"
#include "sts_error_utils.h"
#include "sts_app_manager_utils.h"
#ifdef SUPPORT_GRAPHICS
#ifdef SUPPORT_SCREEN
#include "tokenid_kit.h"
#endif
#endif

namespace OHOS {
namespace AppManagerSts {

static const char* ON_SIGNATURE_FIRST
    = "Lstd/core/String;Lapplication/ApplicationStateObserver/ApplicationStateObserver;Lescompat/Array;:D";
static const char* ON_SIGNATURE_SECOND
    = "Lstd/core/String;Lapplication/ApplicationStateObserver/ApplicationStateObserver;:D";

OHOS::sptr<OHOS::AppExecFwk::IAppMgr> GetAppManagerInstance()
{
    OHOS::sptr<OHOS::ISystemAbilityManager> systemAbilityManager =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    OHOS::sptr<OHOS::IRemoteObject> appObject = systemAbilityManager->GetSystemAbility(OHOS::APP_MGR_SERVICE_ID);
    return OHOS::iface_cast<OHOS::AppExecFwk::IAppMgr>(appObject);
}

#ifdef SUPPORT_SCREEN
    static bool CheckCallerIsSystemApp()
    {
        auto selfToken = IPCSkeleton::GetSelfTokenID();
        if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken)) {
            return false;
        }
        return true;
    }
#endif

static void PreloadApplication(ani_env *env, ani_object callback, ani_string stsBundleName,
    ani_double stsUserId, ani_enum_item stsMode, ani_object stsAppIndex)
{
    TAG_LOGD(AAFwkTag::APPMGR, "PreloadApplication");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "env is null");
        return;
    }
    std::string bundleName;
    if (!OHOS::AppExecFwk::GetStdString(env, stsBundleName, bundleName)) {
        TAG_LOGE(AAFwkTag::APPMGR, "param bundlename err");
        AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM)), nullptr);
        return;
    }
    TAG_LOGD(AAFwkTag::APPMGR, "PreloadApplication userId:%{public}f, bundleName %{public}s",
        stsUserId, bundleName.c_str());
    int32_t userId = static_cast<int32_t>(stsUserId);

    ani_int mode;
    if (!AAFwk::AniEnumConvertUtil::EnumConvertStsToNative(env, stsMode, mode)) {
        TAG_LOGE(AAFwkTag::APPMGR, "param mode err");
        AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM)), nullptr);
        return;
    }
    ani_status status = ANI_OK;
    int32_t appIndex = 0;
    ani_boolean isUndefined = false;
    if ((status = env->Reference_IsUndefined(stsAppIndex, &isUndefined)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "Failed to check undefined status : %{public}d", status);
        return;
    }
    ani_double dval = 0.0;
    if (!isUndefined) {
        if ((status = env->Object_CallMethodByName_Double(stsAppIndex,
            "doubleValue", nullptr, &dval)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::APPMGR, "Object_CallMethodByName_Double status : %{public}d", status);
            return;
        }
        TAG_LOGD(AAFwkTag::APPMGR, "stsAppIndex: %{public}f", dval);
        appIndex = static_cast<int32_t>(dval);
    }
    TAG_LOGD(AAFwkTag::APPMGR, "PreloadApplication userId:%{public}d, mode:%{public}d, appIndex:%{public}d",
        userId, mode, appIndex);

    sptr<OHOS::AppExecFwk::IAppMgr> appMgr = GetAppManagerInstance();
    if (appMgr == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "appManager null ptr");
        AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER)), nullptr);
        return;
    }
    auto ret = appMgr->PreloadApplication(bundleName, userId, static_cast<AppExecFwk::PreloadMode>(mode), appIndex);
    TAG_LOGD(AAFwkTag::APPMGR, "PreloadApplication ret %{public}d", ret);

    AppExecFwk::AsyncCallback(env, callback,
        OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env, static_cast<int32_t>(ret)), nullptr);
    TAG_LOGD(AAFwkTag::APPMGR, "PreloadApplication END");
}

static void GetRunningProcessInformation(ani_env *env, ani_object callback)
{
    TAG_LOGD(AAFwkTag::APPMGR, "GetRunningProcessInformation called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "appManager null ptr");
        return;
    }
    ani_object emptyArray = CreateEmptyAniArray(env);
    sptr<OHOS::AppExecFwk::IAppMgr> appMgr = GetAppManagerInstance();
    if (appMgr == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "appManager null ptr");
        AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER)), emptyArray);
        return;
    }
    std::vector<AppExecFwk::RunningProcessInfo> infos;
    auto ret = appMgr->GetAllRunningProcesses(infos);
    TAG_LOGD(AAFwkTag::APPMGR, "GetAllRunningProcesses ret:%{public}d, size:%{public}d", ret, infos.size());
    if (ret != ERR_OK) {
        AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env, static_cast<int32_t>(ret)), emptyArray);
        return;
    }
    ani_object aniInfosRef = CreateRunningProcessInfoArray(env, infos);
    if (aniInfosRef == nullptr) {
        AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER)), emptyArray);
    } else {
        AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env, static_cast<int32_t>(ret)), aniInfosRef);
    }
    TAG_LOGD(AAFwkTag::APPMGR, "GetRunningProcessInformation finished");
}

static void GetForegroundApplications(ani_env *env, ani_object callback)
{
    TAG_LOGD(AAFwkTag::APPMGR, "GetForegroundApplications called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "env null ptr");
        return;
    }
    ani_object emptyArray = CreateEmptyAniArray(env);
    auto appManager = GetAppManagerInstance();
    if (appManager == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "appManager null ptr");
        AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER)), emptyArray);
        return;
    }
    std::vector<AppExecFwk::AppStateData> appStateData;
    int32_t ret = appManager->GetForegroundApplications(appStateData);
    TAG_LOGD(AAFwkTag::APPMGR, "GetForegroundApplications ret:%{public}d, size:%{public}d", ret, appStateData.size());
    if (ret != ERR_OK) {
        AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env, static_cast<int32_t>(ret)), emptyArray);
        return;
    }
    ani_object appStateDataObj = CreateAppStateDataArray(env, appStateData);
    if (appStateDataObj == nullptr) {
        AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER)), emptyArray);
    } else {
        AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env, static_cast<int32_t>(ret)), appStateDataObj);
    }
    TAG_LOGD(AAFwkTag::APPMGR, "GetForegroundApplications end");
}

static void GetRunningMultiAppInfo(ani_env *env, ani_string stsBundleName, ani_object callback)
{
    TAG_LOGD(AAFwkTag::APPMGR, "GetRunningMultiAppInfo called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "invalid argc");
        return;
    }
    ani_object emtpyMultiAppInfo = CreateEmptyMultiAppInfo(env);
#ifdef SUPPORT_SCREEN
    if (!CheckCallerIsSystemApp()) {
        TAG_LOGE(AAFwkTag::APPMGR, "Non-system app");
        AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_NOT_SYSTEM_APP)), emtpyMultiAppInfo);
    }
#endif
    std::string bundleName;
    if (!OHOS::AppExecFwk::GetStdString(env, stsBundleName, bundleName)) {
        TAG_LOGE(AAFwkTag::APPMGR, "GetStdString Failed");
        AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM)), emtpyMultiAppInfo);
    }
    auto appManager = GetAppManagerInstance();
    if (appManager == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "appManager nullptr");
        AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER)), emtpyMultiAppInfo);
        return;
    }
    AppExecFwk::RunningMultiAppInfo info;
    int32_t innerErrorCode = ERR_OK;
    innerErrorCode = appManager->GetRunningMultiAppInfoByBundleName(bundleName, info);
    TAG_LOGD(AAFwkTag::APPMGR, "GetRunningMultiAppInfoByBundleName ret: %{public}d", innerErrorCode);
    if (innerErrorCode != ERR_OK) {
        AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env,
            static_cast<int32_t>(innerErrorCode)), emtpyMultiAppInfo);
        return;
    }
    ani_object appinfoObj = WrapRunningMultiAppInfo(env, info);
    if (appinfoObj == nullptr) {
        AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER)), emtpyMultiAppInfo);
    } else {
        AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env,
                static_cast<int32_t>(innerErrorCode)), appinfoObj);
    }
    TAG_LOGD(AAFwkTag::APPMGR, "GetRunningMultiAppInfo end");
}

static void GetRunningProcessInfoByBundleNameAndUserId(ani_env *env, ani_string stsBundleName,
    ani_int stsUserId, ani_object callback)
{
    TAG_LOGD(AAFwkTag::APPMGR, "GetRunningProcessInfoByBundleNameAndUserId called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "env null ptr");
        return;
    }
    ani_object emptyArray = CreateEmptyAniArray(env);
    if (stsBundleName == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "stsBundleName null ptr");
        AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM)), emptyArray);
        return;
    }
    std::string bundleName;
    if (!OHOS::AppExecFwk::GetStdString(env, stsBundleName, bundleName)) {
        TAG_LOGE(AAFwkTag::APPMGR, "GetStdString Failed");
        AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM)), emptyArray);
        return;
    }
    int userId = IPCSkeleton::GetCallingUid() / AppExecFwk::Constants::BASE_USER_RANGE;
    if (stsUserId != AppExecFwk::Constants::INVALID_UID) {
        userId = static_cast<int>(stsUserId);
    }
    auto appManager = GetAppManagerInstance();
    if (appManager == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "appManager nullptr");
        AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER)), emptyArray);
        return;
    }
    std::vector<AppExecFwk::RunningProcessInfo> infos;
    int32_t ret = appManager->GetRunningProcessInformation(bundleName, userId, infos);
    TAG_LOGD(AAFwkTag::APPMGR, "GetRunningProcessInformation ret: %{public}d, size:%{public}d", ret, infos.size());
    if (ret != ERR_OK) {
        AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env, static_cast<int32_t>(ret)), emptyArray);
    }
    ani_object aniInfos = CreateRunningProcessInfoArray(env, infos);
    if (aniInfos == nullptr) {
        AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER)), emptyArray);
    } else {
        AppExecFwk::AsyncCallback(env, callback,
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env, static_cast<int32_t>(ret)), aniInfos);
    }
    TAG_LOGD(AAFwkTag::APPMGR, "GetRunningProcessInfoByBundleNameAndUserId finished");
}

static void GetRunningProcessInfoByBundleName(ani_env *env, ani_string stsBundleName,
    ani_object callback)
{
    GetRunningProcessInfoByBundleNameAndUserId(env, stsBundleName, AppExecFwk::Constants::INVALID_UID, callback);
}

static ani_double OnOnApplicationStateInner(ani_env *env, ani_string type,
    ani_object observer, ani_object stsBundleNameList)
{
    TAG_LOGD(AAFwkTag::APPMGR, "OnOnApplicationStateInner called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "env null ptr");
        return ANI_ERROR;
    }
    std::string strType;
    if (!OHOS::AppExecFwk::GetStdString(env, type, strType)) {
        TAG_LOGE(AAFwkTag::APPMGR, "env null ptr");
        AbilityRuntime::ThrowStsErrorByNativeErr(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM));
        return ANI_ERROR;
    }
    auto appManager = GetAppManagerInstance();
    if (appManager == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null appManager");
        AbilityRuntime::ThrowStsErrorByNativeErr(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER));
        return ANI_ERROR;
    }

    std::vector<std::string> bundleNameList;
    if (stsBundleNameList != nullptr) {
        UnWrapArrayString(env, stsBundleNameList, bundleNameList);
    }
    return ANI_OK;
}

static ani_double OnOnApplicationStateFirst(ani_env *env, ani_string type,
    ani_object observer, ani_object stsBundleNameList)
{
    return OnOnApplicationStateInner(env, type, observer, stsBundleNameList);
}

static ani_double OnOnApplicationStateSecond(ani_env *env, ani_string type, ani_object observer)
{
    return OnOnApplicationStateInner(env, type, observer, nullptr);
}

static void OnOff(ani_env *env, [[maybe_unused]]ani_class aniClss)
{
}

void StsAppManagerRegistryInit(ani_env *env)
{
    TAG_LOGD(AAFwkTag::APPMGR, "StsAppManagerRegistryInit call");
    ani_status status = ANI_ERROR;
    if (env->ResetError() != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "ResetError failed");
    }
    ani_namespace ns;
    status = env->FindNamespace("L@ohos/app/ability/appManager/appManager;", &ns);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "FindNamespace appManager failed status : %{public}d", status);
        return;
    }
    std::array kitFunctions = {
        ani_native_function {"nativePreloadApplication", nullptr, reinterpret_cast<void *>(PreloadApplication)},
        ani_native_function {"nativeGetRunningProcessInformation", nullptr,
            reinterpret_cast<void *>(GetRunningProcessInformation)},
        ani_native_function {"nativeGetForegroundApplications", nullptr,
            reinterpret_cast<void *>(GetForegroundApplications)},
        ani_native_function {"nativeGetRunningMultiAppInfo", nullptr,
            reinterpret_cast<void *>(GetRunningMultiAppInfo)},
        ani_native_function {"nativeGetRunningProcessInfoByBundleName", nullptr,
            reinterpret_cast<void *>(GetRunningProcessInfoByBundleName)},
        ani_native_function {"nativeGetRunningProcessInfoByBundleNameAndUserId", nullptr,
            reinterpret_cast<void *>(GetRunningProcessInfoByBundleNameAndUserId)},
        ani_native_function {"nativeOn", ON_SIGNATURE_FIRST, reinterpret_cast<void *>(OnOnApplicationStateFirst)},
        ani_native_function {"nativeOn", ON_SIGNATURE_SECOND, reinterpret_cast<void *>(OnOnApplicationStateSecond)},
        ani_native_function {"nativeOff", nullptr, reinterpret_cast<void *>(OnOff)}
    };

    status = env->Namespace_BindNativeFunctions(ns, kitFunctions.data(), kitFunctions.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "Namespace_BindNativeFunctions failed status : %{public}d", status);
    }
    if (env->ResetError() != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "ResetError failed");
    }
    TAG_LOGD(AAFwkTag::APPMGR, "StsAppManagerRegistryInit end");
}
} // namespace AbilityDelegatorSts
} // namespace OHOS