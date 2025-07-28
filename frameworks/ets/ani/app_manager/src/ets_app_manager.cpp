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

#include "ets_app_manager.h"

#include "ability_manager_client.h"
#include "ability_manager_interface.h"
#include "ani_common_util.h"
#include "ani_enum_convert.h"
#include "app_mgr_constants.h"
#include "app_mgr_interface.h"
#include "ets_app_manager_utils.h"
#include "ets_error_utils.h"
#include "hilog_tag_wrapper.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#ifdef SUPPORT_GRAPHICS
#ifdef SUPPORT_SCREEN
#include "tokenid_kit.h"
#endif
#endif

namespace OHOS {
namespace AppManagerEts {
namespace {
constexpr const char* APP_MANAGER_SPACE_NAME = "L@ohos/app/ability/appManager/appManager;";
}

class EtsAppManager final {
public:
    static void PreloadApplication(ani_env *env, ani_object callback, ani_string aniBundleName, ani_double aniUserId,
        ani_enum_item aniMode, ani_object aniAppIndex);
    static void GetRunningProcessInformation(ani_env *env, ani_object callback);
    static void GetForegroundApplications(ani_env *env, ani_object callback);
    static void GetRunningMultiAppInfo(ani_env *env, ani_string aniBundleName, ani_object callback);
    static void GetRunningProcessInfoByBundleNameAndUserId(ani_env *env, ani_string aniBundleName,
        ani_double aniUserId, ani_object callback);
    static void GetRunningProcessInfoByBundleName(ani_env *env, ani_string aniBundleName, ani_object callback);
private:
    static sptr<AppExecFwk::IAppMgr> GetAppManagerInstance();
#ifdef SUPPORT_SCREEN
    static bool CheckCallerIsSystemApp();
#endif
    static ani_double OnOnApplicationStateInner(
        ani_env *env, ani_string type, ani_object observer, ani_object aniBundleNameList);
};

sptr<AppExecFwk::IAppMgr> EtsAppManager::GetAppManagerInstance()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> appObject = systemAbilityManager->GetSystemAbility(APP_MGR_SERVICE_ID);
    return iface_cast<AppExecFwk::IAppMgr>(appObject);
}

#ifdef SUPPORT_SCREEN
bool EtsAppManager::CheckCallerIsSystemApp()
{
    auto selfToken = IPCSkeleton::GetSelfTokenID();
    return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken);
}
#endif

void EtsAppManager::PreloadApplication(ani_env *env, ani_object callback, ani_string aniBundleName,
    ani_double aniUserId, ani_enum_item aniMode, ani_object aniAppIndex)
{
    TAG_LOGD(AAFwkTag::APPMGR, "PreloadApplication");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "env is null");
        return;
    }
    std::string bundleName;
    if (!AppExecFwk::GetStdString(env, aniBundleName, bundleName)) {
        TAG_LOGE(AAFwkTag::APPMGR, "param bundlename err");
        AppExecFwk::AsyncCallback(env, callback,
            AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(
                env, static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM)), nullptr);
        return;
    }
    TAG_LOGD(AAFwkTag::APPMGR, "PreloadApplication userId:%{public}f, bundleName %{public}s",
        aniUserId, bundleName.c_str());
    int32_t userId = static_cast<int32_t>(aniUserId);

    ani_int mode = 0;
    if (!AAFwk::AniEnumConvertUtil::EnumConvert_EtsToNative(env, aniMode, mode)) {
        TAG_LOGE(AAFwkTag::APPMGR, "param mode err");
        AppExecFwk::AsyncCallback(env, callback,
            AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(
                env, static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM)), nullptr);
        return;
    }

    ani_status status = ANI_OK;
    int32_t appIndex = 0;
    ani_boolean isUndefined = false;
    if ((status = env->Reference_IsUndefined(aniAppIndex, &isUndefined)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "Failed to check undefined status : %{public}d", status);
        return;
    }
    ani_double dval = 0.0;
    if (!isUndefined) {
        if ((status = env->Object_CallMethodByName_Double(aniAppIndex, "doubleValue", nullptr, &dval)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::APPMGR, "Object_CallMethodByName_Double status : %{public}d", status);
            return;
        }
        TAG_LOGD(AAFwkTag::APPMGR, "aniAppIndex: %{public}f", dval);
        appIndex = static_cast<int32_t>(dval);
    }
    TAG_LOGD(AAFwkTag::APPMGR, "PreloadApplication userId:%{public}d, mode:%{public}d, appIndex:%{public}d",
        userId, mode, appIndex);
    sptr<AppExecFwk::IAppMgr> appMgr = GetAppManagerInstance();
    if (appMgr == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "appManager null ptr");
        AppExecFwk::AsyncCallback(env, callback,
            AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(
                env, static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER)), nullptr);
        return;
    }
    auto ret = appMgr->PreloadApplication(bundleName, userId, static_cast<AppExecFwk::PreloadMode>(mode), appIndex);
    TAG_LOGD(AAFwkTag::APPMGR, "PreloadApplication ret %{public}d", ret);

    AppExecFwk::AsyncCallback(env, callback,
        AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, static_cast<int32_t>(ret)), nullptr);
    TAG_LOGD(AAFwkTag::APPMGR, "PreloadApplication END");
}

void EtsAppManager::GetRunningProcessInformation(ani_env *env, ani_object callback)
{
    TAG_LOGD(AAFwkTag::APPMGR, "GetRunningProcessInformation called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "env null ptr");
        return;
    }
    ani_object emptyArray = CreateEmptyAniArray(env);
    sptr<AppExecFwk::IAppMgr> appMgr = GetAppManagerInstance();
    if (appMgr == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "appManager null ptr");
        AppExecFwk::AsyncCallback(env, callback,
            AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(
                env, static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER)), emptyArray);
        return;
    }
    std::vector<AppExecFwk::RunningProcessInfo> infos;
    auto ret = appMgr->GetAllRunningProcesses(infos);
    TAG_LOGD(AAFwkTag::APPMGR, "GetAllRunningProcesses ret:%{public}d, size:%{public}zu", ret, infos.size());
    if (ret != ERR_OK) {
        AppExecFwk::AsyncCallback(env, callback,
            AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, static_cast<int32_t>(ret)), emptyArray);
        return;
    }
    ani_object aniInfosRef = CreateRunningProcessInfoArray(env, infos);
    if (aniInfosRef == nullptr) {
        AppExecFwk::AsyncCallback(env, callback,
            AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(
                env, static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER)), emptyArray);
    } else {
        AppExecFwk::AsyncCallback(env, callback,
            AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, static_cast<int32_t>(ret)), aniInfosRef);
    }
    TAG_LOGD(AAFwkTag::APPMGR, "GetRunningProcessInformation finished");
}

void EtsAppManager::GetForegroundApplications(ani_env *env, ani_object callback)
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
            AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(
                env, static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER)), emptyArray);
        return;
    }
    std::vector<AppExecFwk::AppStateData> appStateData;
    int32_t ret = appManager->GetForegroundApplications(appStateData);
    TAG_LOGD(AAFwkTag::APPMGR, "GetForegroundApplications ret:%{public}d, size:%{public}zu", ret, appStateData.size());
    if (ret != ERR_OK) {
        AppExecFwk::AsyncCallback(env, callback,
            AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, static_cast<int32_t>(ret)), emptyArray);
        return;
    }
    ani_object appStateDataObj = CreateAppStateDataArray(env, appStateData);
    if (appStateDataObj == nullptr) {
        AppExecFwk::AsyncCallback(env, callback,
            AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(
                env, static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER)), emptyArray);
    } else {
        AppExecFwk::AsyncCallback(env, callback,
            AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, static_cast<int32_t>(ret)),
            appStateDataObj);
    }
    TAG_LOGD(AAFwkTag::APPMGR, "GetForegroundApplications end");
}

void EtsAppManager::GetRunningMultiAppInfo(ani_env *env, ani_string aniBundleName, ani_object callback)
{
    TAG_LOGD(AAFwkTag::APPMGR, "GetRunningMultiAppInfo called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "env null ptr");
        return;
    }
    ani_object emptyMultiAppInfo = CreateEmptyMultiAppInfo(env);
#ifdef SUPPORT_SCREEN
    if (!CheckCallerIsSystemApp()) {
        TAG_LOGE(AAFwkTag::APPMGR, "Non-system app");
        AppExecFwk::AsyncCallback(env, callback,
            AbilityRuntime::EtsErrorUtil::CreateError(
                env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_NOT_SYSTEM_APP), emptyMultiAppInfo);
        return;
    }
#endif
    std::string bundleName;
    if (!AppExecFwk::GetStdString(env, aniBundleName, bundleName) || bundleName.empty()) {
        TAG_LOGE(AAFwkTag::APPMGR, "GetStdString Failed");
        AppExecFwk::AsyncCallback(env, callback,
            AbilityRuntime::EtsErrorUtil::CreateError(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM),
            "Parse param bundleName failed, must be a string."), emptyMultiAppInfo);
        return;
    }
    auto appManager = GetAppManagerInstance();
    if (appManager == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "appManager nullptr");
        AppExecFwk::AsyncCallback(env, callback,
            AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(
                env, static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER)), emptyMultiAppInfo);
        return;
    }
    AppExecFwk::RunningMultiAppInfo info;
    int32_t innerErrorCode = ERR_OK;
    innerErrorCode = appManager->GetRunningMultiAppInfoByBundleName(bundleName, info);
    TAG_LOGD(AAFwkTag::APPMGR, "GetRunningMultiAppInfoByBundleName ret: %{public}d", innerErrorCode);
    if (innerErrorCode != ERR_OK) {
        AppExecFwk::AsyncCallback(env, callback,
            AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, innerErrorCode), emptyMultiAppInfo);
        return;
    }
    ani_object appinfoObj = WrapRunningMultiAppInfo(env, info);
    if (appinfoObj == nullptr) {
        AppExecFwk::AsyncCallback(env, callback,
            AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(
                env, static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER)), emptyMultiAppInfo);
    } else {
        AppExecFwk::AsyncCallback(
            env, callback, AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, innerErrorCode), appinfoObj);
    }
    TAG_LOGD(AAFwkTag::APPMGR, "GetRunningMultiAppInfo end");
}

void EtsAppManager::GetRunningProcessInfoByBundleNameAndUserId(
    ani_env *env, ani_string aniBundleName, ani_double aniUserId, ani_object callback)
{
    TAG_LOGD(AAFwkTag::APPMGR, "GetRunningProcessInfoByBundleNameAndUserId called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "env null ptr");
        return;
    }
    ani_object emptyArray = CreateEmptyAniArray(env);
    if (aniBundleName == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "aniBundleName null ptr");
        AppExecFwk::AsyncCallback(env, callback,
            AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(
                env, static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM)), emptyArray);
        return;
    }
    std::string bundleName;
    if (!AppExecFwk::GetStdString(env, aniBundleName, bundleName)) {
        TAG_LOGE(AAFwkTag::APPMGR, "GetStdString Failed");
        AppExecFwk::AsyncCallback(env, callback,
            AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(
                env, static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM)), emptyArray);
        return;
    }
    TAG_LOGD(AAFwkTag::APPMGR, "GetRunningProcessInfoByBundleNameAndUserId userid:%{public}f", aniUserId);
    int32_t userId = static_cast<int32_t>(aniUserId);
    auto appManager = GetAppManagerInstance();
    if (appManager == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "appManager nullptr");
        AppExecFwk::AsyncCallback(env, callback,
            AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(
                env, static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER)), emptyArray);
        return;
    }
    std::vector<AppExecFwk::RunningProcessInfo> infos;
    int32_t ret = appManager->GetRunningProcessInformation(bundleName, userId, infos);
    TAG_LOGD(AAFwkTag::APPMGR, "GetRunningProcessInformation ret: %{public}d, size:%{public}zu", ret, infos.size());
    if (ret != ERR_OK) {
        AppExecFwk::AsyncCallback(env, callback,
            AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, static_cast<int32_t>(ret)), emptyArray);
        return;
    }
    ani_object aniInfos = CreateRunningProcessInfoArray(env, infos);
    if (aniInfos == nullptr) {
        AppExecFwk::AsyncCallback(env, callback,
            AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(
                env, static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER)), emptyArray);
    } else {
        AppExecFwk::AsyncCallback(env, callback,
            AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, static_cast<int32_t>(ret)), aniInfos);
    }
    TAG_LOGD(AAFwkTag::APPMGR, "GetRunningProcessInfoByBundleNameAndUserId finished");
}

void EtsAppManager::GetRunningProcessInfoByBundleName(ani_env *env, ani_string aniBundleName, ani_object callback)
{
    int userId = IPCSkeleton::GetCallingUid() / AppExecFwk::Constants::BASE_USER_RANGE;
    GetRunningProcessInfoByBundleNameAndUserId(env, aniBundleName, static_cast<double>(userId), callback);
}

void EtsAppManagerRegistryInit(ani_env *env)
{
    TAG_LOGD(AAFwkTag::APPMGR, "EtsAppManagerRegistryInit call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "env null ptr");
        return;
    }
    ani_status status = ANI_ERROR;
    if (env->ResetError() != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "ResetError failed");
    }
    ani_namespace ns;
    status = env->FindNamespace(APP_MANAGER_SPACE_NAME, &ns);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "FindNamespace appManager failed status : %{public}d", status);
        return;
    }
    std::array kitFunctions = {
        ani_native_function{
            "nativePreloadApplication", nullptr, reinterpret_cast<void *>(EtsAppManager::PreloadApplication)},
        ani_native_function{"nativeGetRunningProcessInformation",
            nullptr,
            reinterpret_cast<void *>(EtsAppManager::GetRunningProcessInformation)},
        ani_native_function{"nativeGetForegroundApplications",
            nullptr,
            reinterpret_cast<void *>(EtsAppManager::GetForegroundApplications)},
        ani_native_function{
            "nativeGetRunningMultiAppInfo", nullptr, reinterpret_cast<void *>(EtsAppManager::GetRunningMultiAppInfo)},
        ani_native_function{"nativeGetRunningProcessInfoByBundleName",
            nullptr,
            reinterpret_cast<void *>(EtsAppManager::GetRunningProcessInfoByBundleName)},
        ani_native_function{"nativeGetRunningProcessInfoByBundleNameAndUserId",
            nullptr,
            reinterpret_cast<void *>(EtsAppManager::GetRunningProcessInfoByBundleNameAndUserId)}};
    status = env->Namespace_BindNativeFunctions(ns, kitFunctions.data(), kitFunctions.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "Namespace_BindNativeFunctions failed status : %{public}d", status);
    }
    if (env->ResetError() != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "ResetError failed");
    }
    TAG_LOGD(AAFwkTag::APPMGR, "EtsAppManagerRegistryInit end");
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGD(AAFwkTag::APPMGR, "in AppManagerEts.ANI_Constructor");
    if (vm == nullptr || result == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "null vm or result");
        return ANI_INVALID_ARGS;
    }

    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "GetEnv failed, status=%{public}d", status);
        return ANI_NOT_FOUND;
    }
    EtsAppManagerRegistryInit(env);
    *result = ANI_VERSION_1;
    TAG_LOGD(AAFwkTag::APPMGR, "AppManagerEts.ANI_Constructor finished");
    return ANI_OK;
}
}  // extern "C"
}  // namespace AppManagerEts
}  // namespace OHOS