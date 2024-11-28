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

#include "keep_alive_process_manager.h"

#include "ability_util.h"
#include "ffrt.h"
#include "keep_alive_utils.h"
#include "main_element_utils.h"
#include "parameters.h"
#include "permission_constants.h"
#include "process_options.h"

namespace OHOS {
namespace AAFwk {
namespace {
constexpr char PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED[] = "const.product.enterprisefeature.setting.enabled";
constexpr char FOUNDATION_PROCESS_NAME[] = "foundation";
} // namespace

constexpr int32_t CREATE_STATUS_BAR_TIMEOUT_SECONDS = 5; // 5s

KeepAliveProcessManager &KeepAliveProcessManager::GetInstance()
{
    static KeepAliveProcessManager instance;
    return instance;
}

KeepAliveProcessManager::KeepAliveProcessManager() {}

KeepAliveProcessManager::~KeepAliveProcessManager() {}

void KeepAliveProcessManager::StartKeepAliveProcessWithMainElement(std::vector<AppExecFwk::BundleInfo> &bundleInfos,
    int32_t userId)
{
    for (const auto &bundleInfo : bundleInfos) {
        StartKeepAliveProcessWithMainElementPerBundle(bundleInfo, userId);
    }
}

void KeepAliveProcessManager::StartKeepAliveProcessWithMainElementPerBundle(const AppExecFwk::BundleInfo &bundleInfo,
    int32_t userId)
{
    if (!IsKeepAliveBundle(bundleInfo.name, userId)) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "bundle is not set keep-alive");
        return;
    }

    std::string mainElementName;
    if (!MainElementUtils::CheckMainUIAbility(bundleInfo, mainElementName)) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "bundle has no main uiability");
        return;
    }
    KeepAliveAbilityInfo info = {
        .bundleName = bundleInfo.name,
        .moduleName = bundleInfo.entryModuleName,
        .abilityName = mainElementName,
        .userId = userId,
        .appCloneIndex = bundleInfo.appIndex,
    };
    auto ret = StartAbility(info);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "startAbility failed:%{public}d, unsetting keep-alive", ret);
        (void)SetApplicationKeepAlive(bundleInfo.name, userId, false, true);
        return;
    }

    ffrt::submit([bundleInfo, mainElementName, userId]() {
        KeepAliveProcessManager::GetInstance().AfterStartKeepAliveApp(bundleInfo, mainElementName, userId);
    });
}

int32_t KeepAliveProcessManager::StartAbility(const KeepAliveAbilityInfo &info)
{
    Want want;
    want.SetElementName(info.bundleName, info.abilityName);
    want.SetParam(Want::PARAM_APP_CLONE_INDEX_KEY, info.appCloneIndex);
    TAG_LOGI(AAFwkTag::KEEP_ALIVE, "call, bundleName: %{public}s, moduleName: %{public}s, mainElement: %{public}s"
        " appCloneIndex: %{public}d", info.bundleName.c_str(), info.moduleName.c_str(), info.abilityName.c_str(),
        info.appCloneIndex);
    StartOptions options;
    options.processOptions = std::make_shared<ProcessOptions>();
    options.processOptions->isRestartKeepAlive = true;
    options.processOptions->startupVisibility = StartupVisibility::STARTUP_HIDE;
    auto ret = IN_PROCESS_CALL(DelayedSingleton<AbilityManagerService>::GetInstance()->StartAbility(want,
        options, nullptr, info.userId, DEFAULT_INVAL_VALUE));
    MainElementUtils::UpdateMainElement(info.bundleName, info.moduleName, info.abilityName, true, info.userId);
    return ret;
}

void KeepAliveProcessManager::AfterStartKeepAliveApp(const AppExecFwk::BundleInfo &bundleInfo,
    const std::string &mainElementName, int32_t userId)
{
    bool isCreated = false;
    std::shared_ptr<bool> isCanceled = std::make_shared<bool>(false);
    ffrt::condition_variable taskCv;
    ffrt::mutex taskMutex;
    ffrt::submit([&isCreated, &taskCv, &taskMutex, isCanceled,
        accessTokenId = bundleInfo.applicationInfo.accessTokenId, uid = bundleInfo.uid]() {
        while (!DelayedSingleton<AbilityManagerService>::GetInstance()->IsInStatusBar(accessTokenId, uid)) {
            if (!isCanceled || *isCanceled) {
                TAG_LOGE(AAFwkTag::KEEP_ALIVE, "canceled in the middle");
                return;
            }
            usleep(REPOLL_TIME_MICRO_SECONDS);
        }
        if (!isCanceled || *isCanceled) {
            TAG_LOGE(AAFwkTag::KEEP_ALIVE, "canceled");
            return;
        }
        {
            std::lock_guard<ffrt::mutex> lock(taskMutex);
            isCreated = true;
        }
        TAG_LOGI(AAFwkTag::KEEP_ALIVE, "start notify");
        taskCv.notify_all();
        TAG_LOGI(AAFwkTag::KEEP_ALIVE, "finished checking status bar");
    });
    auto condition = [&isCreated, isCanceled] { return (isCreated || (isCanceled && *isCanceled)); };
    {
        std::unique_lock<ffrt::mutex> lock(taskMutex);
        TAG_LOGI(AAFwkTag::KEEP_ALIVE, "wait for condition");
        if (!taskCv.wait_for(lock, std::chrono::seconds(CREATE_STATUS_BAR_TIMEOUT_SECONDS), condition)) {
            TAG_LOGE(AAFwkTag::KEEP_ALIVE, "attach status bar timeout");
            *isCanceled = true;
        }
        TAG_LOGI(AAFwkTag::KEEP_ALIVE, "wait is over");
    }
    if (isCreated) { return; }
    TAG_LOGW(AAFwkTag::KEEP_ALIVE, "not created, cancel keep-alive");
    (void)SetApplicationKeepAlive(bundleInfo.name, userId, false, true);
    (void)DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance()->KillApplication(bundleInfo.name);
}

int32_t KeepAliveProcessManager::SetApplicationKeepAlive(const std::string &bundleName,
    int32_t userId, bool updateEnable, bool isByEDM)
{
    auto result = isByEDM ? CheckPermissionForEDM() : CheckPermission();
    CHECK_RET_RETURN_RET(result, "permission denied");

    CHECK_TRUE_RETURN_RET(bundleName.empty(), INVALID_PARAMETERS_ERR, "input parameter error");

    auto bms = AbilityUtil::GetBundleManagerHelper();
    CHECK_POINTER_AND_RETURN(bms, INNER_ERR);

    auto abilityMgr = DelayedSingleton<AbilityManagerService>::GetInstance();
    CHECK_POINTER_AND_RETURN(abilityMgr, INNER_ERR);
    userId = userId < 0 ? abilityMgr->GetUserId() : userId;
    AppExecFwk::BundleInfo bundleInfo;
    if (!IN_PROCESS_CALL(bms->GetBundleInfo(
        bundleName, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, userId))) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "get bundle info failed");
        return ERR_TARGET_BUNDLE_NOT_EXIST;
    }

    auto appMgrClient = DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance();
    CHECK_POINTER_AND_RETURN(appMgrClient, INNER_ERR);

    bool localEnable = IsKeepAliveBundle(bundleName, userId);
    if (updateEnable) {
        std::string mainElementName;
        CHECK_TRUE_RETURN_RET(!MainElementUtils::CheckMainUIAbility(bundleInfo, mainElementName),
            ERR_NO_MAIN_ABILITY, "bundle has no main uiability");
        CHECK_TRUE_RETURN_RET(!MainElementUtils::CheckStatusBarAbility(bundleInfo),
            ERR_NO_STATUS_BAR_ABILITY, "app has no status bar");
        bool isRunning = false;
        result = IN_PROCESS_CALL(appMgrClient->IsAppRunning(bundleName, 0, isRunning));
        CHECK_RET_RETURN_RET(result, "IsAppRunning failed");
        CHECK_TRUE_RETURN_RET((isRunning && !IsRunningAppInStatusBar(abilityMgr, bundleInfo)),
            ERR_NOT_ATTACHED_TO_STATUS_BAR, "app is not attached to status bar");
    }

    KeepAliveInfo info;
    info.bundleName = bundleName;
    info.userId = userId;
    info.appType = bundleInfo.applicationInfo.isSystemApp ? KeepAliveAppType::SYSTEM : KeepAliveAppType::THIRD_PARTY;
    info.setter = isByEDM ? KeepAliveSetter::SYSTEM : KeepAliveSetter::USER;
    result = AbilityKeepAliveService::GetInstance().SetApplicationKeepAlive(info, updateEnable);
    CHECK_RET_RETURN_RET(result, "set keep-alive failed");
    IN_PROCESS_CALL_WITHOUT_RET(appMgrClient->SetKeepAliveDkv(bundleName, updateEnable, 0));
    if (!updateEnable && localEnable) {
        // just update
        std::vector<AppExecFwk::BundleInfo> bundleInfos{ bundleInfo };
        KeepAliveUtils::NotifyDisableKeepAliveProcesses(bundleInfos, userId);
    }
    return ERR_OK;
}

bool KeepAliveProcessManager::IsRunningAppInStatusBar(std::shared_ptr<AbilityManagerService> abilityMgr,
    const AppExecFwk::BundleInfo &bundleInfo)
{
    CHECK_POINTER_AND_RETURN(abilityMgr, false);

    std::string mainElementName;
    if (!MainElementUtils::CheckMainUIAbility(bundleInfo, mainElementName)) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "bundle has no main uiability");
        return false;
    }
    return abilityMgr->IsInStatusBar(bundleInfo.applicationInfo.accessTokenId, bundleInfo.uid);
}

void KeepAliveProcessManager::OnAppStateChanged(const AppInfo &info)
{
    if (info.state != AppState::BEGIN) {
        TAG_LOGD(AAFwkTag::KEEP_ALIVE, "Not a state of concern. state: %{public}d", info.state);
        return;
    }

    if (info.pid <= 0) {
        TAG_LOGD(AAFwkTag::KEEP_ALIVE, "The obtained application pid is incorrect. state: %{public}d", info.pid);
        return;
    }

    // user 0
    int32_t uid = 0;
    auto appScheduler = DelayedSingleton<AppScheduler>::GetInstance();
    if (appScheduler == nullptr) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "app scheduler error");
        return;
    }
    std::string bundleName;
    appScheduler->GetBundleNameByPid(info.pid, bundleName, uid);
    if (bundleName.empty()) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "get bundle name by pid failed");
        return;
    }

    bool localEnable = IsKeepAliveBundle(bundleName, -1);
    if (!localEnable) {
        return;
    }

    auto appMgrClient = DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance();
    if (appMgrClient == nullptr) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "appMgrClient is null");
        return;
    }
    IN_PROCESS_CALL_WITHOUT_RET(appMgrClient->SetKeepAliveDkv(bundleName, localEnable, uid));
}

bool KeepAliveProcessManager::IsKeepAliveBundle(const std::string &bundleName, int32_t userId)
{
    if (!system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false)) {
        TAG_LOGI(AAFwkTag::KEEP_ALIVE, "not supported");
        return false;
    }
    return AbilityKeepAliveService::GetInstance().IsKeepAliveApp(bundleName, userId);
}

bool KeepAliveProcessManager::GetKeepAliveBundleInfosForUser(std::vector<AppExecFwk::BundleInfo> &bundleInfos,
    int32_t userId)
{
    if (!system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false)) {
        TAG_LOGW(AAFwkTag::KEEP_ALIVE, "not supported");
        return false;
    }
    auto bundleMgrHelper = DelayedSingleton<AppExecFwk::BundleMgrHelper>::GetInstance();
    CHECK_POINTER_AND_RETURN(bundleMgrHelper, false);

    std::vector<KeepAliveInfo> infoList;
    auto ret = AbilityKeepAliveService::GetInstance().GetKeepAliveApplications(userId, infoList);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "failed get keep_alive bundle info: %{public}d", ret);
        return false;
    }
    for (const auto &info: infoList) {
        AppExecFwk::BundleInfo bundleInfo;
        if (!IN_PROCESS_CALL(bundleMgrHelper->GetBundleInfo(info.bundleName,
            AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfo, userId))) {
            TAG_LOGW(AAFwkTag::KEEP_ALIVE, "failed get bundle info: %{public}s", info.bundleName.c_str());
            continue;
        }
        bundleInfos.push_back(bundleInfo);
    }

    return !bundleInfos.empty();
}

int32_t KeepAliveProcessManager::QueryKeepAliveApplications(int32_t appType, int32_t userId,
    std::vector<KeepAliveInfo> &infoList, bool isByEDM)
{
    auto result = isByEDM ? CheckPermissionForEDM() : CheckPermission();
    CHECK_RET_RETURN_RET(result, "permission denied");
    return AbilityKeepAliveService::GetInstance().QueryKeepAliveApplications(userId, appType, infoList);
}

int32_t KeepAliveProcessManager::CheckPermission()
{
    if (!system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false)) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "not supported");
        return ERR_CAPABILITY_NOT_SUPPORT;
    }

    if (!PermissionVerification::GetInstance()->JudgeCallerIsAllowedToUseSystemAPI()) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "not use system-api");
        return ERR_NOT_SYSTEM_APP;
    }

    if (!PermissionVerification::GetInstance()->VerifyCallingPermission(
        PermissionConstants::PERMISSION_MANAGE_APP_KEEP_ALIVE)) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "verify PERMISSION_MANAGE_APP_KEEP_ALIVE fail");
        return CHECK_PERMISSION_FAILED;
    }

    return ERR_OK;
}

int32_t KeepAliveProcessManager::CheckPermissionForEDM()
{
    if (!system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false)) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "not supported");
        return ERR_CAPABILITY_NOT_SUPPORT;
    }
    if (PermissionVerification::GetInstance()->CheckSpecificSystemAbilityAccessPermission(FOUNDATION_PROCESS_NAME)
        || (PermissionVerification::GetInstance()->IsSACall()
        && PermissionVerification::GetInstance()->VerifyCallingPermission(
            PermissionConstants::PERMISSION_MANAGE_APP_KEEP_ALIVE_INTERNAL))) {
        return ERR_OK;
    }
    TAG_LOGE(AAFwkTag::KEEP_ALIVE, "verify PERMISSION_MANAGE_APP_KEEP_ALIVE_INTERNAL fail");
    return CHECK_PERMISSION_FAILED;
}
}  // namespace AAFwk
}  // namespace OHOS
