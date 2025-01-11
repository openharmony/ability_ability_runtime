/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "utils/ability_permission_util.h"

#include "ability_connect_manager.h"
#include "ability_info.h"
#include "ability_util.h"
#include "app_utils.h"
#include "accesstoken_kit.h"
#include "global_constant.h"
#include "hitrace_meter.h"
#include "insight_intent_execute_param.h"
#include "ipc_skeleton.h"
#include "multi_instance_utils.h"
#include "permission_constants.h"
#include "permission_verification.h"
#include "start_ability_utils.h"
#include "utils/app_mgr_util.h"
#ifdef SUPPORT_SCREEN
#include "scene_board_judgement.h"
#include "session_manager_lite.h"
#endif // SUPPORT_SCREEN

using OHOS::Security::AccessToken::AccessTokenKit;

namespace OHOS {
namespace AAFwk {
namespace {
constexpr const char* IS_DELEGATOR_CALL = "isDelegatorCall";
constexpr const char* SETTINGS = "settings";
constexpr int32_t BASE_USER_RANGE = 200000;
}

AbilityPermissionUtil &AbilityPermissionUtil::GetInstance()
{
    static AbilityPermissionUtil instance;
    return instance;
}

inline bool AbilityPermissionUtil::IsDelegatorCall(const AppExecFwk::RunningProcessInfo &processInfo,
    const AbilityRequest &abilityRequest) const
{
    /*  To make sure the AbilityDelegator is not counterfeited
     *   1. The caller-process must be test-process
     *   2. The callerToken must be nullptr
     */
    if (processInfo.isTestProcess &&
        !abilityRequest.callerToken && abilityRequest.want.GetBoolParam(IS_DELEGATOR_CALL, false)) {
        return true;
    }
    return false;
}

bool AbilityPermissionUtil::IsDominateScreen(const Want &want, bool isPendingWantCaller)
{
    if (!isPendingWantCaller &&
        !PermissionVerification::GetInstance()->IsSACall() && !PermissionVerification::GetInstance()->IsShellCall()) {
        auto callerPid = IPCSkeleton::GetCallingPid();
        AppExecFwk::RunningProcessInfo processInfo;
        DelayedSingleton<AppScheduler>::GetInstance()->GetRunningProcessInfoByPid(callerPid, processInfo);
        bool isDelegatorCall = processInfo.isTestProcess && want.GetBoolParam(IS_DELEGATOR_CALL, false);
        if (isDelegatorCall || InsightIntentExecuteParam::IsInsightIntentExecute(want)) {
            TAG_LOGD(AAFwkTag::ABILITYMGR, "not dominate screen.");
            return false;
        }
        // add temporarily
        std::string bundleName = want.GetElement().GetBundleName();
        std::string abilityName = want.GetElement().GetAbilityName();
        bool withoutSettings = bundleName.find(SETTINGS) == std::string::npos &&
            abilityName.find(SETTINGS) == std::string::npos;
        if (withoutSettings && AppUtils::GetInstance().IsAllowStartAbilityWithoutCallerToken(bundleName, abilityName)) {
            TAG_LOGD(AAFwkTag::ABILITYMGR, "not dominate screen, allow.");
            return false;
        } else if (AppUtils::GetInstance().IsAllowStartAbilityWithoutCallerToken(bundleName, abilityName)) {
            auto bms = AbilityUtil::GetBundleManagerHelper();
            CHECK_POINTER_RETURN_BOOL(bms);
            int32_t callerUid = IPCSkeleton::GetCallingUid();
            std::string callerBundleName;
            if (IN_PROCESS_CALL(bms->GetNameForUid(callerUid, callerBundleName)) != ERR_OK) {
                TAG_LOGE(AAFwkTag::ABILITYMGR, "failed to get caller bundle name.");
                return false;
            }
            auto userId = callerUid / BASE_USER_RANGE;
            AppExecFwk::BundleInfo info;
            TAG_LOGD(AAFwkTag::ABILITYMGR, "callerBundleName: %{public}s, userId: %{public}d",
                callerBundleName.c_str(), userId);
            if (!IN_PROCESS_CALL(
                bms->GetBundleInfo(callerBundleName, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, info, userId))) {
                TAG_LOGE(AAFwkTag::ABILITYMGR, "failed to get bundle info.");
                return false;
            }
            if (info.applicationInfo.needAppDetail) {
                TAG_LOGD(AAFwkTag::ABILITYMGR, "not dominate screen, app detail.");
                return false;
            }
        } else if (AppUtils::GetInstance().IsStartOptionsWithAnimation() &&
            PermissionVerification::GetInstance()->VerifyStartSelfUIAbility()) {
            TAG_LOGI(AAFwkTag::ABILITYMGR, "caller from capi.");
            return false;
        }
        TAG_LOGE(AAFwkTag::ABILITYMGR, "dominate screen.");
        return true;
    }
    TAG_LOGD(AAFwkTag::ABILITYMGR, "not dominate screen.");
    return false;
}

int32_t AbilityPermissionUtil::CheckMultiInstanceAndAppClone(Want &want, int32_t userId, int32_t appIndex,
    sptr<IRemoteObject> callerToken)
{
    auto instanceKey = want.GetStringParam(Want::APP_INSTANCE_KEY);
    auto isCreating = want.GetBoolParam(Want::CREATE_APP_INSTANCE_KEY, false);
    AppExecFwk::ApplicationInfo appInfo;
    auto isSupportMultiInstance = AppUtils::GetInstance().IsSupportMultiInstance();
    if (isSupportMultiInstance) {
        if (!StartAbilityUtils::GetApplicationInfo(want.GetBundle(), userId, appInfo)) {
            TAG_LOGI(AAFwkTag::ABILITYMGR, "implicit start");
            return ERR_OK;
        }
        if (appInfo.multiAppMode.multiAppModeType == AppExecFwk::MultiAppModeType::UNSPECIFIED) {
            if (!instanceKey.empty() || isCreating ||
                (appIndex != 0 && appIndex <= AbilityRuntime::GlobalConstant::MAX_APP_CLONE_INDEX)) {
                TAG_LOGE(AAFwkTag::ABILITYMGR, "Not support multi-instance or appClone");
                return ERR_MULTI_APP_NOT_SUPPORTED;
            }
        }
        if (appInfo.multiAppMode.multiAppModeType == AppExecFwk::MultiAppModeType::MULTI_INSTANCE) {
            if (appIndex != 0) {
                TAG_LOGE(AAFwkTag::ABILITYMGR, "Not support appClone");
                return ERR_NOT_SUPPORT_APP_CLONE;
            }
            return CheckMultiInstance(want, callerToken, isCreating, instanceKey, appInfo.multiAppMode.maxCount);
        }
    }
    if (!isSupportMultiInstance || appInfo.multiAppMode.multiAppModeType == AppExecFwk::MultiAppModeType::APP_CLONE) {
        if (!instanceKey.empty() || isCreating) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "Not support multi-instance");
            return ERR_MULTI_INSTANCE_NOT_SUPPORTED;
        }
    }
    return ERR_OK;
}

int32_t AbilityPermissionUtil::CheckMultiInstance(Want &want, sptr<IRemoteObject> callerToken,
    bool isCreating, const std::string &instanceKey, int32_t maxCount)
{
    auto appMgr = AppMgrUtil::GetAppMgr();
    if (appMgr == nullptr) {
        TAG_LOGE(AAFwkTag::FREE_INSTALL, "null appMgr");
        return ERR_INVALID_VALUE;
    }
    auto callerRecord = Token::GetAbilityRecordByToken(callerToken);
    std::vector<std::string> instanceKeyArray;
    auto result = IN_PROCESS_CALL(appMgr->GetAllRunningInstanceKeysByBundleName(want.GetBundle(), instanceKeyArray));
    if (result != ERR_OK) {
        TAG_LOGE(AAFwkTag::FREE_INSTALL, "Failed to get instance key");
        return ERR_INVALID_VALUE;
    }
    // in-app launch
    if (callerRecord != nullptr && callerRecord->GetAbilityInfo().bundleName == want.GetBundle()) {
        if (isCreating) {
            if (!instanceKey.empty()) {
                TAG_LOGE(AAFwkTag::ABILITYMGR, "Not allow to set instanceKey");
                return ERR_APP_INSTANCE_KEY_NOT_SUPPORT;
            }
            if (static_cast<int32_t>(instanceKeyArray.size()) == maxCount) {
                TAG_LOGE(AAFwkTag::ABILITYMGR, "reach upper limit");
                return ERR_UPPER_LIMIT;
            }
            return ERR_OK;
        }
        return UpdateInstanceKey(want, instanceKey, instanceKeyArray, callerRecord->GetInstanceKey());
    }
    // inter-app launch
    if (isCreating) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "not support to create a new instance");
        return ERR_CREATE_NEW_INSTANCE_NOT_SUPPORT;
    }
    std::string defaultInstanceKey = "app_instance_0";
    return UpdateInstanceKey(want, instanceKey, instanceKeyArray, defaultInstanceKey);
}

int32_t AbilityPermissionUtil::UpdateInstanceKey(Want &want, const std::string &originInstanceKey,
    const std::vector<std::string> &instanceKeyArray, const std::string &instanceKey)
{
    if (originInstanceKey.empty()) {
        want.SetParam(Want::APP_INSTANCE_KEY, instanceKey);
        return ERR_OK;
    }
    for (const auto& key : instanceKeyArray) {
        if (key == originInstanceKey) {
            return ERR_OK;
        }
    }
    TAG_LOGE(AAFwkTag::ABILITYMGR, "invalid instanceKey");
    return ERR_INVALID_APP_INSTANCE_KEY;
}

int32_t AbilityPermissionUtil::CheckMultiInstanceKeyForExtension(const AbilityRequest &abilityRequest)
{
    if (abilityRequest.want.GetBoolParam(Want::CREATE_APP_INSTANCE_KEY, false)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "not support to create a new instance");
        return ERR_CREATE_NEW_INSTANCE_NOT_SUPPORT;
    }
    auto instanceKey = MultiInstanceUtils::GetInstanceKey(abilityRequest.want);
    if (instanceKey.empty()) {
        return ERR_OK;
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR, "instanceKey:%{public}s", instanceKey.c_str());
    if (!AppUtils::GetInstance().IsSupportMultiInstance()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "not support multi-instance");
        return ERR_CAPABILITY_NOT_SUPPORT;
    }
    if (!MultiInstanceUtils::IsMultiInstanceApp(abilityRequest.appInfo)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "not multi-instance app");
        return ERR_MULTI_INSTANCE_NOT_SUPPORTED;
    }
    if (MultiInstanceUtils::IsDefaultInstanceKey(instanceKey)) {
        return ERR_OK;
    }
    if (!MultiInstanceUtils::IsSupportedExtensionType(abilityRequest.abilityInfo.extensionAbilityType)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "invalid extension type");
        return ERR_INVALID_EXTENSION_TYPE;
    }
    if (!MultiInstanceUtils::IsInstanceKeyExist(abilityRequest.want.GetBundle(), instanceKey)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "key not found");
        return ERR_INVALID_APP_INSTANCE_KEY;
    }
    return ERR_OK;
}

int32_t AbilityPermissionUtil::CheckStartRecentAbility(const Want &want, AbilityRequest &request)
{
    bool startRecent = want.GetBoolParam(Want::PARAM_RESV_START_RECENT, false);
    if (!startRecent) {
        return ERR_OK;
    }
    if (!AAFwk::PermissionVerification::GetInstance()->JudgeCallerIsAllowedToUseSystemAPI()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "caller no system-app, can not use system-api");
        return ERR_NOT_SYSTEM_APP;
    }
    if (AAFwk::PermissionVerification::GetInstance()->VerifyStartRecentAbilityPermission()) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "Set start recent.");
        request.startRecent = true;
    }
    return ERR_OK;
}

int32_t AbilityPermissionUtil::CheckStartByCallPermissionOrHasFloatingWindow(
    const PermissionVerification::VerificationInfo &verificationInfo, const sptr<IRemoteObject> &callerToken)
{
    int32_t permissionRet =
        PermissionVerification::GetInstance()->CheckStartByCallPermission(verificationInfo);
    if (permissionRet == ERR_OK) {
        return ERR_OK;
    }
#ifdef SUPPORT_SCREEN
    if (CheckStartCallHasFloatingWindow(callerToken) == ERR_OK) {
        return ERR_OK;
    }
#endif // SUPPORT_SCREEN
    return permissionRet;
}

int32_t AbilityPermissionUtil::CheckCallServiceExtensionPermissionOrHasFloatingWindow(
    const PermissionVerification::VerificationInfo &verificationInfo, const sptr<IRemoteObject> &callerToken)
{
    int32_t permissionRet =
        PermissionVerification::GetInstance()->CheckCallServiceExtensionPermission(verificationInfo);
    if (permissionRet == ERR_OK) {
        return ERR_OK;
    }
#ifdef SUPPORT_SCREEN
    if (CheckStartCallHasFloatingWindow(callerToken) == ERR_OK) {
        return ERR_OK;
    }
#endif // SUPPORT_SCREEN
    return permissionRet;
}

int32_t AbilityPermissionUtil::CheckCallAbilityPermissionOrHasFloatingWindow(
    const PermissionVerification::VerificationInfo &verificationInfo, const sptr<IRemoteObject> &callerToken,
    bool isCallByShortcut)
{
    int32_t permissionRet =
        PermissionVerification::GetInstance()->CheckCallAbilityPermission(verificationInfo, isCallByShortcut);
    if (permissionRet == ERR_OK) {
        return ERR_OK;
    }
#ifdef SUPPORT_SCREEN
    if (CheckStartCallHasFloatingWindow(callerToken) == ERR_OK) {
        return ERR_OK;
    }
#endif // SUPPORT_SCREEN
    return permissionRet;
}

#ifdef SUPPORT_SCREEN
int32_t AbilityPermissionUtil::CheckStartCallHasFloatingWindow(const sptr<IRemoteObject> &callerToken)
{
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        auto sceneSessionManager = Rosen::SessionManagerLite::GetInstance().GetSceneSessionManagerLiteProxy();
        bool hasFloatingWindow = false;
        auto err = sceneSessionManager->HasFloatingWindowForeground(callerToken, hasFloatingWindow);
        TAG_LOGI(AAFwkTag::ABILITYMGR,
            "startAbility call from background, checking floatingwindow. Ret: %{public}d", static_cast<int32_t>(err));
        if (err != Rosen::WMError::WM_OK) {
            TAG_LOGE(AAFwkTag::ABILITYMGR,
                "checking floatingwindow err: %{public}d", static_cast<int32_t>(err));
        } else if (hasFloatingWindow) {
            return ERR_OK;
        }
    }
    return CHECK_PERMISSION_FAILED;
}
#endif // SUPPORT_SCREEN
} // AAFwk
} // OHOS