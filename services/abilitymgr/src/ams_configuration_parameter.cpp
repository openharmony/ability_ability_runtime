/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "ams_configuration_parameter.h"

#include <unistd.h>

#include "app_utils.h"
#include "config_policy_utils.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AAFwk {
namespace {
constexpr int32_t LOAD_CONFIGURATION_FAILED = -1;
constexpr int32_t LOAD_CONFIGURATION_SUCCESS = 0;
}

AmsConfigurationParameter::AmsConfigurationParameter() {}

AmsConfigurationParameter &AmsConfigurationParameter::GetInstance()
{
    static AmsConfigurationParameter amsConfiguration;
    return amsConfiguration;
}

void AmsConfigurationParameter::Parse()
{
    auto ref = LoadAmsConfiguration(AmsConfig::AMS_CONFIG_FILE_PATH);

    char buf[MAX_PATH_LEN] = { 0 };
    char *filePath = GetOneCfgFile(AmsConfig::PICKER_CONFIG_FILE_PATH, buf, MAX_PATH_LEN);
    if (filePath == nullptr || filePath[0] == '\0' || strlen(filePath) > MAX_PATH_LEN) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Can not get config file");
        LoadUIExtensionPickerConfig(AmsConfig::PICKER_CONFIG_FILE_PATH_DEFAULT);
        return;
    }
    std::string customConfig = filePath;
    TAG_LOGI(AAFwkTag::ABILITYMGR, "file path: %{private}s", customConfig.c_str());
    LoadUIExtensionPickerConfig(customConfig);
    TAG_LOGI(AAFwkTag::ABILITYMGR, "load config ref : %{private}d", ref);
}

bool AmsConfigurationParameter::NonConfigFile() const
{
    return nonConfigFile_;
}

int AmsConfigurationParameter::GetMissionSaveTime() const
{
    return missionSaveTime_;
}

std::string AmsConfigurationParameter::GetOrientation() const
{
    return orientation_;
}

int AmsConfigurationParameter::GetANRTimeOutTime() const
{
    return anrTime_;
}

int AmsConfigurationParameter::GetAMSTimeOutTime() const
{
    return amsTime_;
}

int AmsConfigurationParameter::GetMaxRestartNum(bool isRootLauncher) const
{
    return (isRootLauncher ? maxRootLauncherRestartNum_ : maxResidentRestartNum_);
}

int AmsConfigurationParameter::GetRestartIntervalTime() const
{
    return restartIntervalTime_;
}

int AmsConfigurationParameter::GetBootAnimationTimeoutTime() const
{
    return bootAnimationTime_;
}

int AmsConfigurationParameter::GetAppStartTimeoutTime() const
{
    return timeoutUnitTime_ * AppUtils::GetInstance().GetTimeoutUnitTimeRatio();
}

void AmsConfigurationParameter::SetPickerJsonObject(cJSON *jsonObject)
{
    cJSON *pickerConfigurationItem = cJSON_GetObjectItem(jsonObject, AmsConfig::PICKER_CONFIGURATION);
    if (jsonObject != nullptr) {
        pickerJsonObject_ = cJSON_Duplicate(pickerConfigurationItem, true);
    }
}

cJSON *AmsConfigurationParameter::GetPickerJsonObject() const
{
    return pickerJsonObject_;
}

const std::map<std::string, std::string>& AmsConfigurationParameter::GetPickerMap() const
{
    return picker_;
}

void AmsConfigurationParameter::LoadUIExtensionPickerConfig(const std::string &filePath)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "%{public}s", __func__);
    if (filePath.empty()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "empty file path");
        return;
    }

    if (access(filePath.c_str(), F_OK) != 0) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "can not access the file: %{private}s", filePath.c_str());
        return;
    }
    std::ifstream inFile;
    inFile.open(filePath, std::ios::in);
    if (!inFile.is_open()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "read picker config error");
        return;
    }
    std::string fileContent((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    cJSON *pickerJson = cJSON_Parse(fileContent.c_str());
    if (pickerJson == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "json parse error");
        return;
    }

    cJSON *uieatensionItem = cJSON_GetObjectItem(pickerJson, AmsConfig::UIEATENSION);
    if (uieatensionItem == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "json config not contains the key");
        cJSON_Delete(pickerJson);
        return;
    }
    if (!cJSON_IsArray(uieatensionItem)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "invalid obj");
        cJSON_Delete(pickerJson);
        return;
    }
    int size = cJSON_GetArraySize(uieatensionItem);
    if (size == 0) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "invalid obj");
        cJSON_Delete(pickerJson);
        return;
    }

    for (int i = 0; i < size; i++) {
        cJSON *extensionItem = cJSON_GetArrayItem(uieatensionItem, i);
        if (extensionItem == nullptr || !cJSON_IsObject(extensionItem)) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "invalid obj");
            continue;
        }
        cJSON *uieatensionTypeItem = cJSON_GetObjectItem(extensionItem, AmsConfig::UIEATENSION_TYPE);
        cJSON *uieatensionTypePickerItem = cJSON_GetObjectItem(extensionItem, AmsConfig::UIEATENSION_TYPE_PICKER);
        if (uieatensionTypeItem == nullptr || !cJSON_IsString(uieatensionTypeItem) ||
            uieatensionTypePickerItem == nullptr || !cJSON_IsString(uieatensionTypePickerItem)) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "invalid key or value");
            continue;
        }
        std::string type = uieatensionTypeItem->valuestring;
        std::string typePicker = uieatensionTypePickerItem->valuestring;
        TAG_LOGI(AAFwkTag::ABILITYMGR, "type: %{public}s, typePicker: %{public}s", type.c_str(), typePicker.c_str());
        picker_[type] = typePicker;
    }
    cJSON_Delete(pickerJson);
    TAG_LOGI(AAFwkTag::ABILITYMGR, "read config success");
}

int AmsConfigurationParameter::LoadAmsConfiguration(const std::string &filePath)
{
    int ret[2] = {0};
    if (filePath.empty()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "empty file path");
        return READ_FAIL;
    }

    if (access(filePath.c_str(), F_OK) != 0) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "can not access the file: %{private}s", filePath.c_str());
        return READ_FAIL;
    }
    std::ifstream inFile;
    inFile.open(filePath, std::ios::in);
    if (!inFile.is_open()) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "error");
        nonConfigFile_ = true;
        return READ_FAIL;
    }

    std::string fileContent((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();
    
    cJSON *amsJson = cJSON_Parse(fileContent.c_str());
    if (amsJson == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "json parse error");
        nonConfigFile_ = true;
        return READ_JSON_FAIL;
    }

    ret[0] = LoadAppConfigurationForStartUpService(amsJson);
    if (ret[0] != 0) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "LoadAppConfigurationForStartUpService return error");
    }

    ret[1] = LoadAppConfigurationForMemoryThreshold(amsJson);
    if (ret[1] != 0) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "LoadAppConfigurationForMemoryThreshold return error");
    }

    LoadSystemConfiguration(amsJson);
    LoadBackToCallerConfig(amsJson);
    LoadSupportSCBCrashRebootConfig(amsJson);
    LoadSupportAAKillWithReasonConfig(amsJson);
    SetPickerJsonObject(amsJson);
    cJSON_Delete(amsJson);

    for (const auto& i : ret) {
        if (i != 0) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "json no have service item ...");
            return READ_JSON_FAIL;
        }
    }

    TAG_LOGI(AAFwkTag::ABILITYMGR, "reading ability manager service config success");
    return READ_OK;
}

int AmsConfigurationParameter::LoadAppConfigurationForStartUpService(cJSON *jsonObject)
{
    cJSON *amsItem = cJSON_GetObjectItem(jsonObject, AmsConfig::SERVICE_ITEM_AMS);
    if (amsItem == nullptr) {
        return LOAD_CONFIGURATION_FAILED;
    }
    UpdateStartUpServiceConfigInteger(jsonObject, AmsConfig::MISSION_SAVE_TIME, missionSaveTime_);
    UpdateStartUpServiceConfigInteger(jsonObject, AmsConfig::APP_NOT_RESPONSE_PROCESS_TIMEOUT_TIME, anrTime_);
    UpdateStartUpServiceConfigInteger(jsonObject, AmsConfig::AMS_TIMEOUT_TIME, amsTime_);
    UpdateStartUpServiceConfigInteger(jsonObject, AmsConfig::ROOT_LAUNCHER_RESTART_MAX, maxRootLauncherRestartNum_);
    UpdateStartUpServiceConfigInteger(jsonObject, AmsConfig::RESIDENT_RESTART_MAX, maxResidentRestartNum_);
    UpdateStartUpServiceConfigInteger(jsonObject, AmsConfig::RESTART_INTERVAL_TIME, restartIntervalTime_);
    UpdateStartUpServiceConfigInteger(jsonObject, AmsConfig::BOOT_ANIMATION_TIMEOUT_TIME, bootAnimationTime_);
    UpdateStartUpServiceConfigInteger(jsonObject, AmsConfig::TIMEOUT_UNIT_TIME, timeoutUnitTime_);
    UpdateStartUpServiceConfigInteger(jsonObject, AmsConfig::MULTI_USER_TYPE, multiUserType_);
    return LOAD_CONFIGURATION_SUCCESS;
}

int AmsConfigurationParameter::LoadAppConfigurationForMemoryThreshold(cJSON *jsonObject)
{
    int ret = 0;
    cJSON *memoryThresholdItem = cJSON_GetObjectItem(jsonObject, "memorythreshold");
    if (memoryThresholdItem == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "LoadAppConfigurationForMemoryThreshold return error");
        ret = -1;
    }

    return ret;
}

int AmsConfigurationParameter::LoadSystemConfiguration(cJSON *jsonObject)
{
    cJSON *systemConfigurationItem = cJSON_GetObjectItem(jsonObject, AmsConfig::SYSTEM_CONFIGURATION);
    if (systemConfigurationItem != nullptr) {
        cJSON *systemOrientationItem = cJSON_GetObjectItem(systemConfigurationItem, AmsConfig::SYSTEM_ORIENTATION);
        if (systemOrientationItem != nullptr && cJSON_IsString(systemOrientationItem)) {
            orientation_ = systemOrientationItem->valuestring;
            return READ_OK;
        }
    }
    return READ_FAIL;
}

int32_t AmsConfigurationParameter::LoadBackToCallerConfig(cJSON *jsonObject)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "load backTocaller config");
    cJSON *supportBackToCallerItem = cJSON_GetObjectItem(jsonObject, AmsConfig::SUPPORT_BACK_TO_CALLER);
    if (supportBackToCallerItem != nullptr && cJSON_IsBool(supportBackToCallerItem)) {
        supportBackToCaller_ = supportBackToCallerItem->type == cJSON_True;
        return READ_OK;
    }
    TAG_LOGE(AAFwkTag::ABILITYMGR, "load backTocaller failed");
    return READ_FAIL;
}

int32_t AmsConfigurationParameter::LoadSupportAAKillWithReasonConfig(cJSON *jsonObject)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "load SupportAAKillWithReason config");
    cJSON *supportAAKillWithReasonItem = cJSON_GetObjectItem(jsonObject, AmsConfig::SUPPORT_AA_KILL_WITH_REASON);
    if (supportAAKillWithReasonItem != nullptr && cJSON_IsBool(supportAAKillWithReasonItem)) {
        supportAAKillWithReason_ = supportAAKillWithReasonItem->type == cJSON_True;
        return READ_OK;
    }
    TAG_LOGE(AAFwkTag::ABILITYMGR, "load SupportAAKillWithReason failed");
    return READ_FAIL;
}

bool AmsConfigurationParameter::IsSupportBackToCaller() const
{
    return supportBackToCaller_;
}

bool AmsConfigurationParameter::IsSupportAAKillWithReason() const
{
    return supportAAKillWithReason_;
}

int32_t AmsConfigurationParameter::LoadSupportSCBCrashRebootConfig(cJSON *jsonObject)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "load scb_crash_reboot_config config");
    cJSON *suportScbCrashRebootItem = cJSON_GetObjectItem(jsonObject, AmsConfig::SUPPORT_SCB_CRASH_REBOOT);
    if (suportScbCrashRebootItem != nullptr && cJSON_IsBool(suportScbCrashRebootItem)) {
        supportSceneboardCrashReboot_ = suportScbCrashRebootItem->type == cJSON_True;
        return READ_OK;
    }
    TAG_LOGE(AAFwkTag::ABILITYMGR, "load scb_crash_reboot_config failed");
    return READ_FAIL;
}

bool AmsConfigurationParameter::IsSupportSCBCrashReboot() const
{
    return supportSceneboardCrashReboot_;
}

bool AmsConfigurationParameter::CheckServiceConfigEnable(cJSON *jsonObject, const std::string &configName,
    JsonValueType type)
{
    cJSON *amsItem = cJSON_GetObjectItem(jsonObject, AmsConfig::SERVICE_ITEM_AMS);
    if (amsItem != nullptr) {
        cJSON *configItem = cJSON_GetObjectItem(amsItem, configName.c_str());
        if (configItem == nullptr) {
            return false;
        }
        switch (type) {
            case JsonValueType::NUMBER: {
                return cJSON_IsNumber(configItem);
            }
            case JsonValueType::STRING: {
                return cJSON_IsString(configItem);
            }
            case JsonValueType::BOOLEAN: {
                return cJSON_IsBool(configItem);
            }
            default: {
                return false;
            }
        }
    }
    return false;
}

void AmsConfigurationParameter::UpdateStartUpServiceConfigInteger(cJSON *jsonObject,
    const std::string &configName, int32_t &value)
{
    cJSON *amsItem = cJSON_GetObjectItem(jsonObject, AmsConfig::SERVICE_ITEM_AMS);
    if (amsItem != nullptr) {
        cJSON *configItem = cJSON_GetObjectItem(amsItem, configName.c_str());
        if (configItem != nullptr && cJSON_IsNumber(configItem)) {
            value = static_cast<int32_t>(configItem->valuedouble);
        }
    }
}

void AmsConfigurationParameter::UpdateStartUpServiceConfigString(cJSON *jsonObject,
    const std::string &configName, std::string &value)
{
    cJSON *amsItem = cJSON_GetObjectItem(jsonObject, AmsConfig::SERVICE_ITEM_AMS);
    if (amsItem != nullptr && cJSON_IsObject(amsItem)) {
        cJSON *configItem = cJSON_GetObjectItem(amsItem, configName.c_str());
        if (configItem != nullptr && cJSON_IsString(configItem)) {
            value = configItem->valuestring;
        }
    }
}

int AmsConfigurationParameter::MultiUserType() const
{
    return multiUserType_;
}
}  // namespace AAFwk
}  // namespace OHOS
