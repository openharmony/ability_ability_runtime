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
            if (!IN_PROCESS_CALL(
                bms->GetBundleInfo(callerBundleName, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, info, userId))) {
                TAG_LOGE(AAFwkTag::ABILITYMGR, "failed to get bundle info.");
                return false;
            }
            if (info.applicationInfo.needAppDetail) {
                TAG_LOGD(AAFwkTag::ABILITYMGR, "not dominate screen, app detail.");
                return false;
            }
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
    auto isSupportMultiInstance = AppUtils::GetInstance().IsSupportMultiInstance();
    auto isCreating = want.GetBoolParam(Want::CREATE_APP_INSTANCE_KEY, false);
    if (!isSupportMultiInstance) {
        if (!instanceKey.empty() || isCreating) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "Not support multi-instance");
            return ERR_MULTI_INSTANCE_NOT_SUPPORTED;
        }
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