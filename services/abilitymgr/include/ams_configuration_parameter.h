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

#ifndef OHOS_ABILITY_RUNTIME_AMS_CONFIGURATION_PARAMETER_H
#define OHOS_ABILITY_RUNTIME_AMS_CONFIGURATION_PARAMETER_H

#include <fstream>
#include <map>

#include "cJSON.h"
#include "nocopyable.h"
#include "parameters.h"

namespace OHOS {
namespace AAFwk {
namespace AmsConfig {
constexpr const char* AMS_CONFIG_FILE_PATH = "/system/etc/ams_service_config.json";
constexpr const char* PICKER_CONFIG_FILE_PATH_DEFAULT = "/system/etc/uiextension_picker_config.json";
constexpr const char* PICKER_CONFIG_FILE_PATH = "/etc/uiextension_picker_config.json";
constexpr const char* SERVICE_ITEM_AMS = "service_startup_config";
constexpr const char* MISSION_SAVE_TIME = "mission_save_time";
constexpr const char* APP_NOT_RESPONSE_PROCESS_TIMEOUT_TIME = "app_not_response_process_timeout_time";
constexpr const char* AMS_TIMEOUT_TIME = "ams_timeout_time";
constexpr const char* DEVICE_TYPE = "device_type";
constexpr const char* SYSTEM_CONFIGURATION = "system_configuration";
constexpr const char* SYSTEM_ORIENTATION = "system_orientation";
constexpr const char* ROOT_LAUNCHER_RESTART_MAX = "root_launcher_restart_max";
constexpr const char* RESIDENT_RESTART_MAX = "resident_restart_max";
constexpr const char* RESTART_INTERVAL_TIME = "restart_interval_time";
constexpr const char* BOOT_ANIMATION_TIMEOUT_TIME = "boot_animation_timeout_time";
constexpr const char* TIMEOUT_UNIT_TIME = "timeout_unit_time";
constexpr const char* ABILITY_NAME = "ability_name";
constexpr const char* BUNDLE_NAME = "bundle_name";
constexpr const char* PICKER_CONFIGURATION = "picker_configuration";
constexpr const char* PICKER_TYPE = "picker_type";
constexpr const char* UIEATENSION = "uiextension";
constexpr const char* UIEATENSION_TYPE = "type";
constexpr const char* UIEATENSION_TYPE_PICKER = "typePicker";
constexpr const char* MULTI_USER_TYPE = "multiUserType";
constexpr const char* SUPPORT_BACK_TO_CALLER = "supportBackToCaller";
constexpr const char* SUPPORT_SCB_CRASH_REBOOT = "supportSCBCrashReboot";
constexpr const char* SUPPORT_AA_KILL_WITH_REASON = "supportAAKillWithReason";
}  // namespace AmsConfig

enum class SatrtUiMode { STATUSBAR = 1, NAVIGATIONBAR = 2, STARTUIBOTH = 3 };

enum class JsonValueType {
    NULLABLE,
    BOOLEAN,
    NUMBER,
    OBJECT,
    ARRAY,
    STRING
};

class AmsConfigurationParameter final {
public:
    enum { READ_OK = 0, READ_FAIL = 1, READ_JSON_FAIL = 2 };

    static AmsConfigurationParameter &GetInstance();
    /**
     * return true : ams no config file
     * return false : ams have config file
     */
    bool NonConfigFile() const;
    /**
     * Get profile information
     */
    void Parse();

    /**
     * Get the save time of the current content
     */
    int GetMissionSaveTime() const;

    /**
     * Get current system direction parameters, Temporary method.
     */
    std::string GetOrientation() const;

    /**
     * Get the max number of restart.
     */
    int GetMaxRestartNum(bool isRootLauncher) const;

    /**
     * Get the interval time after restart out of the max number of restart.
     */
    int GetRestartIntervalTime() const;

    /**
     * get the application not response process timeout time.
     */
    int GetANRTimeOutTime() const;

    /**
     * get ability manager service not response process timeout time.
     */
    int GetAMSTimeOutTime() const;

    /**
     * get boot animation stared timout time.
     */
    int GetBootAnimationTimeoutTime() const;

    /**
     * get the application cold start timeout time.
     */
    int GetAppStartTimeoutTime() const;

    bool IsSupportBackToCaller() const;

    bool IsSupportSCBCrashReboot() const;

    bool IsSupportAAKillWithReason() const;

    /**
     * set picker json object.
     */
    void SetPickerJsonObject(cJSON *jsonObject);

    /**
     * get picker json object.
     */
    cJSON *GetPickerJsonObject() const;

    int MultiUserType() const;

    const std::map<std::string, std::string>& GetPickerMap() const;

private:
    AmsConfigurationParameter();
    ~AmsConfigurationParameter() = default;
    DISALLOW_COPY_AND_MOVE(AmsConfigurationParameter);
    /**
     * Read the configuration file of ams
     *
     */
    int LoadAmsConfiguration(const std::string &filePath);
    int LoadAppConfigurationForStartUpService(cJSON *Object);
    int LoadAppConfigurationForMemoryThreshold(cJSON *Object);
    int LoadSystemConfiguration(cJSON *Object);
    void LoadPickerConfiguration(cJSON *Object);
    bool CheckServiceConfigEnable(cJSON *Object, const std::string &configName, JsonValueType type);
    void UpdateStartUpServiceConfigInteger(cJSON *Object, const std::string &configName, int32_t &value);
    void UpdateStartUpServiceConfigString(cJSON *Object, const std::string &configName, std::string &value);
    void UpdatePickerConfigurationString(cJSON *Object, const std::string &configName, std::string &value);
    void LoadUIExtensionPickerConfig(const std::string &filePath);
    int32_t LoadBackToCallerConfig(cJSON *Object);
    int32_t LoadSupportAAKillWithReasonConfig(cJSON *Object);
    int32_t LoadSupportSCBCrashRebootConfig(cJSON *Object);

private:
    bool nonConfigFile_ {false};
    bool supportBackToCaller_ {true};
    bool supportSceneboardCrashReboot_{true};
    bool supportAAKillWithReason_{false};

    int maxRootLauncherRestartNum_ = 0;
    int maxResidentRestartNum_ = 0;
    int restartIntervalTime_ {120000};
    int missionSaveTime_ {12 * 60 * 60 * 1000};
    int anrTime_ {5000};
    int amsTime_ {5000};
    int bootAnimationTime_ {5};
    int timeoutUnitTime_ {1000};
    int multiUserType_ {0};

    std::string orientation_ {""};
    std::string bundleName_ {""};
    std::string abilityName_ {""};
    std::string pickerType_ {""};
    std::map<std::string, std::string> picker_;
    cJSON *pickerJsonObject_ = nullptr;
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_AMS_CONFIGURATION_PARAMETER_H
