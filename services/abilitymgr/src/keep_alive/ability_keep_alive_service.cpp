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

#include "ability_keep_alive_service.h"

#include "ability_keep_alive_data_manager.h"
#include "ability_manager_service.h"
#include "ability_util.h"
#include "hilog_tag_wrapper.h"
#include "in_process_call_wrapper.h"
#include "main_element_utils.h"
#include "permission_constants.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AAFwk;
namespace {
constexpr char PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED[] = "const.product.enterprisefeature.setting.enabled";
} // namespace

AbilityKeepAliveService::AbilityKeepAliveService() {}

AbilityKeepAliveService::~AbilityKeepAliveService() {}

int32_t AbilityKeepAliveService::SetApplicationKeepAlive(KeepAliveInfo &info, bool flag)
{
    TAG_LOGD(AAFwkTag::KEEP_ALIVE, "SetApplicationKeepAlive is called,"
        " bundleName: %{public}s, userId: %{public}d, flag: %{public}d",
        info.bundleName.c_str(), info.userId, static_cast<int>(flag));
    int32_t code = CheckPermission();
    if (code != ERR_OK) {
        return code;
    }

    GetValidUserId(info.userId);
    info.appType = KeepAliveAppType::APP;
    info.setter = KeepAliveSetter::USER;

    if (flag) {
        return SetKeepAliveTrue(info);
    }
    return CancelKeepAlive(info);
}

int32_t AbilityKeepAliveService::SetKeepAliveTrue(const KeepAliveInfo &info)
{
    auto bundleMgrHelper = AbilityUtil::GetBundleManagerHelper();
    if (bundleMgrHelper == nullptr) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "null bundleMgrHelper");
        return INNER_ERR;
    }

    // check main element
    AppExecFwk::BundleInfo bundleInfo;
    if (!IN_PROCESS_CALL(bundleMgrHelper->GetBundleInfo(info.bundleName,
        AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfo, info.userId))) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "failed get bundle info");
        return ERR_TARGET_BUNDLE_NOT_EXIST;
    }
    std::string mainElementName;
    if (!MainElementUtils::CheckMainUIAbility(bundleInfo, mainElementName)) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "bundle has no main uiability");
        return ERR_NO_MAIN_ABILITY;
    }

    KeepAliveStatus status = AbilityKeepAliveDataManager::GetInstance().QueryKeepAliveData(info);
    if (status.code != ERR_OK && status.code != ERR_NAME_NOT_FOUND) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "QueryKeepAliveData fail");
        return status.code;
    }

    if (status.code == ERR_OK) {
        TAG_LOGI(AAFwkTag::KEEP_ALIVE, "app is already set");
        return status.code;
    }

    return AbilityKeepAliveDataManager::GetInstance().InsertKeepAliveData(info);
}

int32_t AbilityKeepAliveService::CancelKeepAlive(const KeepAliveInfo &info)
{
    KeepAliveStatus status = AbilityKeepAliveDataManager::GetInstance().QueryKeepAliveData(info);
    if (status.code != ERR_OK) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "QueryKeepAliveData fail");
        return status.code;
    }

    if (!status.isKeepAlive) {
        return ERR_TARGET_BUNDLE_NOT_EXIST;
    }

    return AbilityKeepAliveDataManager::GetInstance().DeleteKeepAliveData(info);
}

int32_t AbilityKeepAliveService::QueryKeepAliveApplications(int32_t userId,
    int32_t appType, std::vector<KeepAliveInfo> &infoList)
{
    int32_t code = CheckPermission();
    if (code != ERR_OK) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "permission verification fail");
        return code;
    }

    GetValidUserId(userId);
    KeepAliveInfo queryParam;
    queryParam.userId = userId;
    queryParam.appType = KeepAliveAppType(appType);
    queryParam.setter = KeepAliveSetter::USER;
    return AbilityKeepAliveDataManager::GetInstance().QueryKeepAliveApplications(
        queryParam, infoList);
}

int32_t AbilityKeepAliveService::QueryKeepAliveApplicationsByEDM(int32_t userId,
    int32_t appType, std::vector<KeepAliveInfo> &infoList)
{
    int32_t code = CheckPermissionForEDM();
    if (code != ERR_OK) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "permission verification fail");
        return code;
    }

    GetValidUserId(userId);
    KeepAliveInfo queryParam;
    queryParam.userId = userId;
    queryParam.appType = KeepAliveAppType(appType);
    queryParam.setter = KeepAliveSetter::SYSTEM;
    return AbilityKeepAliveDataManager::GetInstance().QueryKeepAliveApplications(
        queryParam, infoList);
}

int32_t AbilityKeepAliveService::SetApplicationKeepAliveByEDM(KeepAliveInfo &info, bool flag)
{
    TAG_LOGD(AAFwkTag::KEEP_ALIVE, "SetApplicationKeepAliveByEDM is called,"
        " bundleName: %{public}s, userId: %{public}d, flag: %{public}d",
        info.bundleName.c_str(), info.userId, static_cast<int>(flag));
    int32_t code = CheckPermissionForEDM();
    if (code != ERR_OK) {
        return code;
    }

    GetValidUserId(info.userId);
    info.appType = KeepAliveAppType::APP;
    info.setter = KeepAliveSetter::SYSTEM;

    if (flag) {
        return SetKeepAliveTrue(info);
    }
    return CancelKeepAlive(info);
}

void AbilityKeepAliveService::GetValidUserId(int32_t &userId)
{
    if (userId >= 0) {
        return;
    }
    auto abilityMgr = DelayedSingleton<AbilityManagerService>::GetInstance();
    if (abilityMgr == nullptr) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "null abilityMgr");
        return;
    }

    if (userId < 0) {
        userId = abilityMgr->GetUserId();
    }
}

int32_t AbilityKeepAliveService::CheckPermission()
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

int32_t AbilityKeepAliveService::CheckPermissionForEDM()
{
    if (!system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false)) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "not supported");
        return ERR_CAPABILITY_NOT_SUPPORT;
    }
    if (!PermissionVerification::GetInstance()->IsSACall() ||
        !PermissionVerification::GetInstance()->VerifyCallingPermission(
            PermissionConstants::PERMISSION_MANAGE_APP_KEEP_ALIVE_INTERNAL)) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "verify PERMISSION_MANAGE_APP_KEEP_ALIVE_INTERNAL fail");
        return CHECK_PERMISSION_FAILED;
    }
    return ERR_OK;
}

int32_t AbilityKeepAliveService::GetKeepAliveProcessEnable(const std::string &bundleName, int32_t userId,
    bool &isKeepAlive)
{
    if (!system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false)) {
        TAG_LOGI(AAFwkTag::KEEP_ALIVE, "not supported");
        isKeepAlive = false;
        return ERR_OK;
    }

    if (bundleName.empty()) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "bundle name empty");
        return ERR_INVALID_VALUE;
    }

    GetValidUserId(userId);
    KeepAliveInfo info;
    info.bundleName = bundleName;
    info.userId = userId;
    KeepAliveStatus status = AbilityKeepAliveDataManager::GetInstance().QueryKeepAliveData(info);
    if (status.code != ERR_OK) {
        TAG_LOGE(AAFwkTag::KEEP_ALIVE, "QueryKeepAliveData fail");
        return status.code;
    }
    isKeepAlive = status.isKeepAlive;
    return ERR_OK;
}

int32_t AbilityKeepAliveService::GetKeepAliveApplications(int32_t userId, std::vector<KeepAliveInfo> &infoList)
{
    if (!system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false)) {
        TAG_LOGI(AAFwkTag::KEEP_ALIVE, "not supported");
        return ERR_OK;
    }
    KeepAliveInfo queryParam;
    queryParam.userId = userId;
    return AbilityKeepAliveDataManager::GetInstance().QueryKeepAliveApplications(
        queryParam, infoList);
}
} // namespace AbilityRuntime
} // namespace OHOS
