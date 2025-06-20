/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "module_profile.h"

#include <algorithm>
#include <mutex>
#include <set>
#include <sstream>

#include "bundle_constants.h"
#include "bundle_info.h"
#include "common_profile.h"
#include "hilog_tag_wrapper.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
const std::unordered_map<std::string, ExtensionAbilityType> EXTENSION_TYPE_MAP = {
    { "form", ExtensionAbilityType::FORM },
    { "workScheduler", ExtensionAbilityType::WORK_SCHEDULER },
    { "inputMethod", ExtensionAbilityType::INPUTMETHOD },
    { "service", ExtensionAbilityType::SERVICE },
    { "accessibility", ExtensionAbilityType::ACCESSIBILITY },
    { "dataShare", ExtensionAbilityType::DATASHARE },
    { "fileShare", ExtensionAbilityType::FILESHARE },
    { "staticSubscriber", ExtensionAbilityType::STATICSUBSCRIBER },
    { "fence", ExtensionAbilityType::FENCE },
    { "wallpaper", ExtensionAbilityType::WALLPAPER },
    { "backup", ExtensionAbilityType::BACKUP },
    { "window", ExtensionAbilityType::WINDOW },
    { "enterpriseAdmin", ExtensionAbilityType::ENTERPRISE_ADMIN },
    { "fileAccess", ExtensionAbilityType::FILEACCESS_EXTENSION },
    { "thumbnail", ExtensionAbilityType::THUMBNAIL },
    { "preview", ExtensionAbilityType::PREVIEW_TYPE },
    { "print", ExtensionAbilityType::PRINT },
    { "push", ExtensionAbilityType::PUSH },
    { "driver", ExtensionAbilityType::DRIVER },
    { "appAccountAuthorization", ExtensionAbilityType::APP_ACCOUNT_AUTHORIZATION },
    { "ui", ExtensionAbilityType::UI },
    { "sysDialog/userAuth", ExtensionAbilityType::SYSDIALOG_USERAUTH },
    { "sysDialog/common", ExtensionAbilityType::SYSDIALOG_COMMON },
    { "sysPicker/mediaControl", ExtensionAbilityType::SYSPICKER_MEDIACONTROL },
    { "sysDialog/atomicServicePanel", ExtensionAbilityType::SYSDIALOG_ATOMICSERVICEPANEL },
    { "sysPicker/share", ExtensionAbilityType::SYSPICKER_SHARE },
    { "hms/account", ExtensionAbilityType::HMS_ACCOUNT },
    { "distributed", ExtensionAbilityType::DISTRIBUTED }
};

ExtensionAbilityType ConvertToExtensionAbilityType(const std::string &type)
{
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "called");
    if (EXTENSION_TYPE_MAP.find(type) != EXTENSION_TYPE_MAP.end()) {
        return EXTENSION_TYPE_MAP.at(type);
    }

    return ExtensionAbilityType::UNSPECIFIED;
}

std::string ConvertToExtensionTypeName(ExtensionAbilityType type)
{
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "called");
    for (const auto &[key, val] : EXTENSION_TYPE_MAP) {
        if (val == type) {
            return key;
        }
    }

    return "Unspecified";
}

namespace Profile {
int32_t g_parseResult = ERR_OK;
std::mutex g_mutex;

const std::set<std::string> MODULE_TYPE_SET = {
    "entry",
    "feature",
    "shared"
};

const std::set<std::string> VIRTUAL_MACHINE_SET = {
    "ark",
    "default"
};

const std::map<std::string, uint32_t> BACKGROUND_MODES_MAP = {
    {ProfileReader::KEY_DATA_TRANSFER, ProfileReader::VALUE_DATA_TRANSFER},
    {ProfileReader::KEY_AUDIO_PLAYBACK, ProfileReader::VALUE_AUDIO_PLAYBACK},
    {ProfileReader::KEY_AUDIO_RECORDING, ProfileReader::VALUE_AUDIO_RECORDING},
    {ProfileReader::KEY_LOCATION, ProfileReader::VALUE_LOCATION},
    {ProfileReader::KEY_BLUETOOTH_INTERACTION, ProfileReader::VALUE_BLUETOOTH_INTERACTION},
    {ProfileReader::KEY_MULTI_DEVICE_CONNECTION, ProfileReader::VALUE_MULTI_DEVICE_CONNECTION},
    {ProfileReader::KEY_WIFI_INTERACTION, ProfileReader::VALUE_WIFI_INTERACTION},
    {ProfileReader::KEY_VOIP, ProfileReader::VALUE_VOIP},
    {ProfileReader::KEY_TASK_KEEPING, ProfileReader::VALUE_TASK_KEEPING},
    {ProfileReader::KEY_PICTURE_IN_PICTURE, ProfileReader::VALUE_PICTURE_IN_PICTURE},
    {ProfileReader::KEY_SCREEN_FETCH, ProfileReader::VALUE_SCREEN_FETCH}
};

const std::set<std::string> GRANT_MODE_SET = {
    "system_grant",
    "user_grant"
};

const std::set<std::string> AVAILABLE_LEVEL_SET = {
    "system_core",
    "system_basic",
    "normal"
};

const std::map<std::string, LaunchMode> LAUNCH_MODE_MAP = {
    {"singleton", LaunchMode::SINGLETON},
    {"standard", LaunchMode::STANDARD},
    {"multiton", LaunchMode::STANDARD},
    {"specified", LaunchMode::SPECIFIED}
};
const std::unordered_map<std::string, DisplayOrientation> DISPLAY_ORIENTATION_MAP = {
    {"unspecified", DisplayOrientation::UNSPECIFIED},
    {"landscape", DisplayOrientation::LANDSCAPE},
    {"portrait", DisplayOrientation::PORTRAIT},
    {"landscape_inverted", DisplayOrientation::LANDSCAPE_INVERTED},
    {"portrait_inverted", DisplayOrientation::PORTRAIT_INVERTED},
    {"auto_rotation", DisplayOrientation::AUTO_ROTATION},
    {"auto_rotation_landscape", DisplayOrientation::AUTO_ROTATION_LANDSCAPE},
    {"auto_rotation_portrait", DisplayOrientation::AUTO_ROTATION_PORTRAIT},
    {"auto_rotation_restricted", DisplayOrientation::AUTO_ROTATION_RESTRICTED},
    {"auto_rotation_landscape_restricted", DisplayOrientation::AUTO_ROTATION_LANDSCAPE_RESTRICTED},
    {"auto_rotation_portrait_restricted", DisplayOrientation::AUTO_ROTATION_PORTRAIT_RESTRICTED},
    {"locked", DisplayOrientation::LOCKED}
};
const std::unordered_map<std::string, SupportWindowMode> WINDOW_MODE_MAP = {
    {"fullscreen", SupportWindowMode::FULLSCREEN},
    {"split", SupportWindowMode::SPLIT},
    {"floating", SupportWindowMode::FLOATING}
};
const std::unordered_map<std::string, BundleType> BUNDLE_TYPE_MAP = {
    {"app", BundleType::APP},
    {"atomicService", BundleType::ATOMIC_SERVICE},
    {"shared", BundleType::SHARED}
};

struct DeviceConfig {
    // pair first : if exist in module.json then true, otherwise false
    // pair second : actual value
    std::pair<bool, int32_t> minAPIVersion = std::make_pair<>(false, 0);
    std::pair<bool, bool> keepAlive = std::make_pair<>(false, false);
    std::pair<bool, bool> removable = std::make_pair<>(false, true);
    std::pair<bool, bool> singleton = std::make_pair<>(false, false);
    std::pair<bool, bool> userDataClearable = std::make_pair<>(false, true);
    std::pair<bool, bool> accessible = std::make_pair<>(false, true);
};

struct Metadata {
    std::string name;
    std::string value;
    std::string resource;
};

struct Ability {
    std::string name;
    std::string srcEntrance;
    std::string launchType = ABILITY_LAUNCH_TYPE_DEFAULT_VALUE;
    std::string description;
    int32_t descriptionId = 0;
    std::string icon;
    int32_t iconId = 0;
    std::string label;
    int32_t labelId = 0;
    int32_t priority = 0;
    std::vector<std::string> permissions;
    std::vector<Metadata> metadata;
    bool visible = false;
    bool continuable = false;
    std::vector<std::string> backgroundModes;
    std::string startWindowIcon;
    int32_t startWindowIconId = 0;
    std::string startWindowBackground;
    int32_t startWindowBackgroundId = 0;
    bool removeMissionAfterTerminate = false;
    std::string orientation = "unspecified";
    std::vector<std::string> windowModes;
    double maxWindowRatio = 0;
    double minWindowRatio = 0;
    uint32_t maxWindowWidth = 0;
    uint32_t minWindowWidth = 0;
    uint32_t maxWindowHeight = 0;
    uint32_t minWindowHeight = 0;
    bool excludeFromMissions = false;
    bool recoverable = false;
    bool unclearableMission = false;
};

struct Extension {
    std::string name;
    std::string srcEntrance;
    std::string icon;
    int32_t iconId = 0;
    std::string label;
    int32_t labelId = 0;
    std::string description;
    int32_t descriptionId = 0;
    int32_t priority = 0;
    std::string type;
    std::string readPermission;
    std::string writePermission;
    std::string uri;
    std::vector<std::string> permissions;
    bool visible = false;
    std::vector<Metadata> metadata;
};

struct App {
    std::string bundleName;
    bool debug = false;
    std::string icon;
    int32_t iconId = 0;
    std::string label;
    int32_t labelId = 0;
    std::string description;
    int32_t descriptionId = 0;
    std::string vendor;
    int32_t versionCode = 0;
    std::string versionName;
    int32_t minCompatibleVersionCode = -1;
    uint32_t minAPIVersion = 0;
    int32_t targetAPIVersion = 0;
    std::string apiReleaseType = APP_API_RELEASETYPE_DEFAULT_VALUE;
    bool keepAlive = false;
    std::pair<bool, bool> removable = std::make_pair<>(false, true);
    bool singleton = false;
    bool userDataClearable = true;
    bool accessible = false;
    std::vector<std::string> targetBundleList;
    std::map<std::string, DeviceConfig> deviceConfigs;
    bool multiProjects = false;
    std::string targetBundle;
    int32_t targetPriority = 0;
    bool asanEnabled = false;
    std::string bundleType = Profile::BUNDLE_TYPE_APP;
    std::string compileSdkVersion;
    std::string compileSdkType = Profile::COMPILE_SDK_TYPE_OPEN_HARMONY;
};

struct Module {
    std::string name;
    std::string type;
    std::string srcEntrance;
    std::string description;
    int32_t descriptionId = 0;
    std::string process;
    std::string mainElement;
    std::vector<std::string> deviceTypes;
    bool deliveryWithInstall = false;
    bool installationFree = false;
    std::string virtualMachine = MODULE_VIRTUAL_MACHINE_DEFAULT_VALUE;
    std::string pages;
    std::vector<Metadata> metadata;
    std::vector<Ability> abilities;
    std::vector<Extension> extensionAbilities;
    std::vector<Dependency> dependencies;
    std::string compileMode;
    bool isLibIsolated = false;
    std::string targetModule;
    int32_t targetPriority = 0;
    std::vector<ProxyData> proxyDatas;
    std::vector<ProxyData> proxyData;
    std::string buildHash;
    std::string isolationMode;
    bool compressNativeLibs = true;
};

struct ModuleJson {
    App app;
    Module module;
};

void from_json(const cJSON *jsonObject, Metadata &metadata)
{
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "read metadata tag from module.json");
    GetStringValueIfFindKey(jsonObject, META_DATA_NAME, metadata.name, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, META_DATA_VALUE, metadata.value, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, META_DATA_RESOURCE, metadata.resource, false, g_parseResult);
}

void from_json(const cJSON *jsonObject, Ability &ability)
{
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "read ability tag from module.json");
    GetStringValueIfFindKey(jsonObject, ABILITY_NAME, ability.name, true, g_parseResult);
    // both srcEntry and srcEntrance can be configured, but srcEntry has higher priority
    cJSON *srcEntryItem = cJSON_GetObjectItem(jsonObject, SRC_ENTRY);
    if (srcEntryItem != nullptr) {
        GetStringValueIfFindKey(jsonObject, SRC_ENTRY, ability.srcEntrance, true, g_parseResult);
    } else {
        GetStringValueIfFindKey(jsonObject, SRC_ENTRANCE, ability.srcEntrance, true, g_parseResult);
    }
    GetStringValueIfFindKey(jsonObject, ABILITY_LAUNCH_TYPE, ability.launchType, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, DESCRIPTION, ability.description, false, g_parseResult);
    GetNumberValueIfFindKey(jsonObject, DESCRIPTION_ID, ability.descriptionId, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, ICON, ability.icon, false, g_parseResult);
    GetNumberValueIfFindKey(jsonObject, ICON_ID, ability.iconId, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, LABEL, ability.label, false, g_parseResult);
    GetNumberValueIfFindKey(jsonObject, LABEL_ID, ability.labelId, false, g_parseResult);
    GetNumberValueIfFindKey(jsonObject, PRIORITY, ability.priority, false, g_parseResult);
    GetStringValuesIfFindKey(jsonObject, PERMISSIONS, ability.permissions, false, g_parseResult);
    GetObjectValuesIfFindKey(jsonObject, META_DATA, ability.metadata, false, g_parseResult);
    // both exported and visible can be configured, but exported has higher priority
    GetBoolValueIfFindKey(jsonObject, VISIBLE, ability.visible, false, g_parseResult);
    GetBoolValueIfFindKey(jsonObject, EXPORTED, ability.visible, false, g_parseResult);
    GetBoolValueIfFindKey(jsonObject, ABILITY_CONTINUABLE, ability.continuable, false, g_parseResult);
    GetStringValuesIfFindKey(jsonObject, ABILITY_BACKGROUNDMODES, ability.backgroundModes, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, ABILITY_START_WINDOW_ICON, ability.startWindowIcon, false, g_parseResult);
    GetNumberValueIfFindKey(jsonObject, ABILITY_START_WINDOW_ICON_ID, ability.startWindowIconId, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, ABILITY_START_WINDOW_BACKGROUND, ability.startWindowBackground, false,
        g_parseResult);
    GetNumberValueIfFindKey(jsonObject, ABILITY_START_WINDOW_BACKGROUND_ID, ability.startWindowBackgroundId, false,
        g_parseResult);
    GetBoolValueIfFindKey(jsonObject, ABILITY_REMOVE_MISSION_AFTER_TERMINATE, ability.removeMissionAfterTerminate,
        false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, ABILITY_ORIENTATION, ability.orientation, false, g_parseResult);
    GetStringValuesIfFindKey(jsonObject, ABILITY_SUPPORT_WINDOW_MODE, ability.windowModes, false, g_parseResult);
    GetNumberValueIfFindKey(jsonObject, ABILITY_MAX_WINDOW_RATIO, ability.maxWindowRatio, false, g_parseResult);
    GetNumberValueIfFindKey(jsonObject, ABILITY_MIN_WINDOW_RATIO, ability.minWindowRatio, false, g_parseResult);
    GetNumberValueIfFindKey(jsonObject, ABILITY_MAX_WINDOW_WIDTH, ability.maxWindowWidth, false, g_parseResult);
    GetNumberValueIfFindKey(jsonObject, ABILITY_MIN_WINDOW_WIDTH, ability.minWindowWidth, false, g_parseResult);
    GetNumberValueIfFindKey(jsonObject, ABILITY_MAX_WINDOW_HEIGHT, ability.maxWindowHeight, false, g_parseResult);
    GetNumberValueIfFindKey(jsonObject, ABILITY_MIN_WINDOW_HEIGHT, ability.minWindowHeight, false, g_parseResult);
    GetBoolValueIfFindKey(jsonObject, ABILITY_EXCLUDE_FROM_MISSIONS, ability.excludeFromMissions, false, g_parseResult);
    GetBoolValueIfFindKey(jsonObject, ABILITY_RECOVERABLE, ability.recoverable, false, g_parseResult);
    GetBoolValueIfFindKey(jsonObject, ABILITY_UNCLEARABLE_MISSION, ability.unclearableMission, false, g_parseResult);
}

void from_json(const cJSON *jsonObject, Extension &extension)
{
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "read extension tag from module.json");
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "jsonObject is null");
        return false;
    }
    GetStringValueIfFindKey(jsonObject, EXTENSION_ABILITY_NAME, extension.name, true, g_parseResult);
    // both srcEntry and srcEntrance can be configured, but srcEntry has higher priority
    cJSON *srcEntryItem = cJSON_GetObjectItem(jsonObject, SRC_ENTRY);
    if (srcEntryItem != nullptr) {
        GetStringValueIfFindKey(jsonObject, SRC_ENTRY, extension.srcEntrance, true, g_parseResult);
    } else {
        GetStringValueIfFindKey(jsonObject, SRC_ENTRANCE, extension.srcEntrance, true, g_parseResult);
    }
    GetStringValueIfFindKey(jsonObject, ICON, extension.icon, false, g_parseResult);
    GetNumberValueIfFindKey(jsonObject, ICON_ID, extension.iconId, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, LABEL, extension.label, false, g_parseResult);
    GetNumberValueIfFindKey(jsonObject, LABEL_ID, extension.labelId, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, DESCRIPTION, extension.description, false, g_parseResult);
    GetNumberValueIfFindKey(jsonObject, DESCRIPTION_ID, extension.descriptionId, false, g_parseResult);
    GetNumberValueIfFindKey(jsonObject, PRIORITY, extension.priority, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, EXTENSION_ABILITY_TYPE, extension.type, true, g_parseResult);
    GetStringValueIfFindKey(jsonObject, EXTENSION_ABILITY_READ_PERMISSION, extension.readPermission, false,
        g_parseResult);
    GetStringValueIfFindKey(jsonObject, EXTENSION_ABILITY_WRITE_PERMISSION, extension.writePermission, false,
        g_parseResult);
    GetStringValueIfFindKey(jsonObject, EXTENSION_URI, extension.uri, false, g_parseResult);
    GetStringValuesIfFindKey(jsonObject, PERMISSIONS, extension.permissions, false, g_parseResult);
    // both exported and visible can be configured, but exported has higher priority
    GetBoolValueIfFindKey(jsonObject, VISIBLE, extension.visible, false, g_parseResult);
    GetBoolValueIfFindKey(jsonObject, EXPORTED, extension.visible, false, g_parseResult);
    GetObjectValuesIfFindKey(jsonObject, META_DATA, extension.metadata, false, g_parseResult);
    if (g_parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "g_parseResult:%{public}d", g_parseResult);
        return false;
    }
    return true;
}

void from_json(const cJSON *jsonObject, DeviceConfig &deviceConfig)
{
    cJSON *minApiVersionItem = cJSON_GetObjectItem(jsonObject, MIN_API_VERSION);
    if (minApiVersionItem != nullptr) {
        deviceConfig.minAPIVersion.first = true;
        GetNumberValueIfFindKey(jsonObject, MIN_API_VERSION, deviceConfig.minAPIVersion.second, false, g_parseResult);
    }
    cJSON *deviceConfigKeepAliveItem = cJSON_GetObjectItem(jsonObject, DEVICE_CONFIG_KEEP_ALIVE);
    if (deviceConfigKeepAliveItem != nullptr) {
        deviceConfig.keepAlive.first = true;
        GetBoolValueIfFindKey(jsonObject, DEVICE_CONFIG_KEEP_ALIVE, deviceConfig.keepAlive.second, false,
            g_parseResult);
    }
    cJSON *deviceConfigRemovableItem = cJSON_GetObjectItem(jsonObject, DEVICE_CONFIG_REMOVABLE);
    if (deviceConfigRemovableItem != nullptr) {
        deviceConfig.removable.first = true;
        GetBoolValueIfFindKey(jsonObject, DEVICE_CONFIG_REMOVABLE, deviceConfig.removable.second, false, g_parseResult);
    }
    cJSON *deviceConfigSingletonItem = cJSON_GetObjectItem(jsonObject, DEVICE_CONFIG_SINGLETON);
    if (deviceConfigSingletonItem != nullptr) {
        deviceConfig.singleton.first = true;
        GetBoolValueIfFindKey(jsonObject, DEVICE_CONFIG_SINGLETON, deviceConfig.singleton.second, false, g_parseResult);
    }
    cJSON *deviceConfigUserDataClearableItem = cJSON_GetObjectItem(jsonObject, DEVICE_CONFIG_USER_DATA_CLEARABLE);
    if (deviceConfigUserDataClearableItem != nullptr) {
        deviceConfig.userDataClearable.first = true;
        GetBoolValueIfFindKey(jsonObject, DEVICE_CONFIG_USER_DATA_CLEARABLE, deviceConfig.userDataClearable.second,
            false, g_parseResult);
    }
    cJSON *deviceConfigAccessibleItem = cJSON_GetObjectItem(jsonObject, DEVICE_CONFIG_ACCESSIBLE);
    if (deviceConfigAccessibleItem != nullptr) {
        deviceConfig.accessible.first = true;
        GetBoolValueIfFindKey(jsonObject, DEVICE_CONFIG_ACCESSIBLE, deviceConfig.accessible.second, false,
            g_parseResult);
    }
}

void from_json(const cJSON *jsonObject, App &app)
{
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "read app tag from module.json");
    GetStringValueIfFindKey(jsonObject, APP_BUNDLE_NAME, app.bundleName, true, g_parseResult);
    GetStringValueIfFindKey(jsonObject, ICON, app.icon, true, g_parseResult);
    GetStringValueIfFindKey(jsonObject, LABEL, app.label, true, g_parseResult);
    GetNumberValueIfFindKey(jsonObject, APP_VERSION_CODE, app.versionCode, true, g_parseResult);
    GetStringValueIfFindKey(jsonObject, APP_VERSION_NAME, app.versionName, true, g_parseResult);
    GetNumberValueIfFindKey(jsonObject, APP_MIN_API_VERSION, app.minAPIVersion, true, g_parseResult);
    GetNumberValueIfFindKey(jsonObject, APP_TARGET_API_VERSION, app.targetAPIVersion, true, g_parseResult);
    GetBoolValueIfFindKey(jsonObject, APP_DEBUG, app.debug, false, g_parseResult);
    GetNumberValueIfFindKey(jsonObject, ICON_ID, app.iconId, false, g_parseResult);
    GetNumberValueIfFindKey(jsonObject, LABEL_ID, app.labelId, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, DESCRIPTION, app.description, false, g_parseResult);
    GetNumberValueIfFindKey(jsonObject, DESCRIPTION_ID, app.descriptionId, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, APP_VENDOR, app.vendor, false, g_parseResult);
    GetNumberValueIfFindKey(jsonObject, APP_MIN_COMPATIBLE_VERSION_CODE, app.minCompatibleVersionCode, false,
        g_parseResult);
    GetStringValueIfFindKey(jsonObject, APP_API_RELEASETYPE, app.apiReleaseType, false, g_parseResult);
    GetBoolValueIfFindKey(jsonObject, APP_KEEP_ALIVE, app.keepAlive, false, g_parseResult);
    cJSON *appRemovableItem = cJSON_GetObjectItem(jsonObject, APP_REMOVABLE);
    if (appRemovableItem != nullptr) {
        app.removable.first = true;
        GetBoolValueIfFindKey(jsonObject, APP_REMOVABLE, app.removable.second, false, g_parseResult);
    }
    GetBoolValueIfFindKey(jsonObject, APP_SINGLETON, app.singleton, false, g_parseResult);
    GetBoolValueIfFindKey(jsonObject, APP_USER_DATA_CLEARABLE, app.userDataClearable, false, g_parseResult);
    GetBoolValueIfFindKey(jsonObject, APP_ACCESSIBLE, app.accessible, false, g_parseResult);
    GetBoolValueIfFindKey(jsonObject, APP_ASAN_ENABLED, app.asanEnabled, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, BUNDLE_TYPE, app.bundleType, false, g_parseResult);
    cJSON *appPhoneItem = cJSON_GetObjectItem(jsonObject, APP_PHONE);
    if (appPhoneItem != nullptr) {
        DeviceConfig deviceConfig;
        GetObjectValueIfFindKey(jsonObject, APP_PHONE, deviceConfig, false, g_parseResult);
        app.deviceConfigs[APP_PHONE] = deviceConfig;
    }
    cJSON *appTableItem = cJSON_GetObjectItem(jsonObject, APP_TABLET);
    if (appTableItem != nullptr) {
        DeviceConfig deviceConfig;
        GetObjectValueIfFindKey(jsonObject, APP_TABLET, deviceConfig, false, g_parseResult);
        app.deviceConfigs[APP_TABLET] = deviceConfig;
    }
    cJSON *appTvItem = cJSON_GetObjectItem(jsonObject, APP_TV);
    if (appTvItem != nullptr) {
        DeviceConfig deviceConfig;
        GetObjectValueIfFindKey(jsonObject, APP_TV, deviceConfig, false, g_parseResult);
        app.deviceConfigs[APP_TV] = deviceConfig;
    }
    cJSON *appWearableItem = cJSON_GetObjectItem(jsonObject, APP_WEARABLE);
    if (appWearableItem != nullptr) {
        DeviceConfig deviceConfig;
        GetObjectValueIfFindKey(jsonObject, APP_WEARABLE, deviceConfig, false, g_parseResult);
        app.deviceConfigs[APP_WEARABLE] = deviceConfig;
    }
    cJSON *appLiteWearableItem = cJSON_GetObjectItem(jsonObject, APP_LITE_WEARABLE);
    if (appLiteWearableItem != nullptr) {
        DeviceConfig deviceConfig;
        GetObjectValueIfFindKey(jsonObject, APP_LITE_WEARABLE, deviceConfig, false, g_parseResult);
        app.deviceConfigs[APP_LITE_WEARABLE] = deviceConfig;
    }
    cJSON *appCarItem = cJSON_GetObjectItem(jsonObject, APP_CAR);
    if (appCarItem != nullptr) {
        DeviceConfig deviceConfig;
        GetObjectValueIfFindKey(jsonObject, APP_CAR, deviceConfig, false, g_parseResult);
        app.deviceConfigs[APP_CAR] = deviceConfig;
    }
    cJSON *appSmartVersionItem = cJSON_GetObjectItem(jsonObject, APP_SMART_VISION);
    if (appSmartVersionItem != nullptr) {
        DeviceConfig deviceConfig;
        GetObjectValueIfFindKey(jsonObject, APP_SMART_VISION, deviceConfig, false, g_parseResult);
        app.deviceConfigs[APP_SMART_VISION] = deviceConfig;
    }
    cJSON *appRouterItem = cJSON_GetObjectItem(jsonObject, APP_ROUTER);
    if (appRouterItem != nullptr) {
        DeviceConfig deviceConfig;
        GetObjectValueIfFindKey(jsonObject, APP_ROUTER, deviceConfig, false, g_parseResult);
        app.deviceConfigs[APP_ROUTER] = deviceConfig;
    }
    GetBoolValueIfFindKey(jsonObject, APP_MULTI_PROJECTS, app.multiProjects, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, APP_TARGET_BUNDLE_NAME, app.targetBundle, false, g_parseResult);
    GetNumberValueIfFindKey(jsonObject, APP_TARGET_PRIORITY, app.targetPriority, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, COMPILE_SDK_VERSION, app.compileSdkVersion, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, COMPILE_SDK_TYPE, app.compileSdkType, false, g_parseResult);
}

void from_json(const cJSON *jsonObject, Module &module)
{
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "read module tag from module.json");
    GetStringValueIfFindKey(jsonObject, MODULE_NAME, module.name, true, g_parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_TYPE, module.type, true, g_parseResult);
    GetStringValuesIfFindKey(jsonObject, MODULE_DEVICE_TYPES, module.deviceTypes, true, g_parseResult);
    GetBoolValueIfFindKey(jsonObject, MODULE_DELIVERY_WITH_INSTALL, module.deliveryWithInstall, true, g_parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_PAGES, module.pages, false, g_parseResult);
    // both srcEntry and srcEntrance can be configured, but srcEntry has higher priority
    cJSON *srcEntryItem = cJSON_GetObjectItem(jsonObject, SRC_ENTRY);
    if (srcEntryItem != nullptr) {
        GetStringValueIfFindKey(jsonObject, SRC_ENTRY, module.srcEntrance, false, g_parseResult);
    } else {
        GetStringValueIfFindKey(jsonObject, SRC_ENTRANCE, module.srcEntrance, false, g_parseResult);
    }
    GetStringValueIfFindKey(jsonObject, DESCRIPTION, module.description, false, g_parseResult);
    GetNumberValueIfFindKey(jsonObject, DESCRIPTION_ID, module.descriptionId, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_PROCESS, module.process, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_MAIN_ELEMENT, module.mainElement, false, g_parseResult);
    GetBoolValueIfFindKey(jsonObject, MODULE_INSTALLATION_FREE, module.installationFree, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_VIRTUAL_MACHINE, module.virtualMachine, false, g_parseResult);
    GetObjectValuesIfFindKey(jsonObject, META_DATA, module.metadata, false, g_parseResult);
    GetObjectValuesIfFindKey(jsonObject, MODULE_ABILITIES, module.abilities, false, g_parseResult);
    GetObjectValuesIfFindKey(jsonObject, MODULE_EXTENSION_ABILITIES, module.extensionAbilities, false, g_parseResult);
    GetObjectValuesIfFindKey(jsonObject, MODULE_DEPENDENCIES, module.dependencies, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_COMPILE_MODE, module.compileMode, false, g_parseResult);
    GetBoolValueIfFindKey(jsonObject, MODULE_IS_LIB_ISOLATED, module.isLibIsolated, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_TARGET_MODULE_NAME, module.targetModule, false, g_parseResult);
    GetNumberValueIfFindKey(jsonObject, MODULE_TARGET_PRIORITY, module.targetPriority, false, g_parseResult);
    GetObjectValuesIfFindKey(jsonObject, MODULE_PROXY_DATAS, module.proxyDatas, false, g_parseResult);
    GetObjectValuesIfFindKey(jsonObject, MODULE_PROXY_DATA, module.proxyData, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_BUILD_HASH, module.buildHash, false, g_parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_ISOLATION_MODE, module.isolationMode, false, g_parseResult);
}

void from_json(const cJSON *jsonObject, ModuleJson &moduleJson)
{
    GetObjectValueIfFindKey(jsonObject, APP, moduleJson.app, true, g_parseResult);
    GetObjectValueIfFindKey(jsonObject, MODULE, moduleJson.module, true, g_parseResult);
}
} // namespace Profile

namespace {
struct TransformParam {
    bool isSystemApp = false;
    bool isPreInstallApp = false;
};

void GetMetadata(std::vector<Metadata> &metadata, const std::vector<Profile::Metadata> &profileMetadata)
{
    for (const Profile::Metadata &item : profileMetadata) {
        Metadata tmpMetadata;
        tmpMetadata.name = item.name;
        tmpMetadata.value = item.value;
        tmpMetadata.resource = item.resource;
        metadata.emplace_back(tmpMetadata);
    }
}

bool CheckBundleNameIsValid(const std::string &bundleName)
{
    if (bundleName.empty()) {
        return false;
    }
    if (bundleName.size() < Constants::MIN_BUNDLE_NAME || bundleName.size() > Constants::MAX_BUNDLE_NAME) {
        return false;
    }
    char head = bundleName.at(0);
    if (!isalpha(head)) {
        return false;
    }
    for (const auto &c : bundleName) {
        if (!isalnum(c) && (c != '.') && (c != '_')) {
            return false;
        }
    }
    return true;
}

bool CheckModuleNameIsValid(const std::string &moduleName)
{
    if (moduleName.empty()) {
        return false;
    }
    if (moduleName.size() > Constants::MAX_MODULE_NAME) {
        return false;
    }
    if (moduleName.find(Constants::RELATIVE_PATH) != std::string::npos) {
        return false;
    }
    if (moduleName.find(Constants::MODULE_NAME_SEPARATOR) != std::string::npos) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "module name contain");
        return false;
    }
    return true;
}

Resource GetResource(const std::string &bundleName, const std::string &moduleName, int32_t resId)
{
    Resource resource;
    resource.bundleName = bundleName;
    resource.moduleName = moduleName;
    resource.id = resId;
    return resource;
}

bool ToApplicationInfo(
    const Profile::ModuleJson &moduleJson,
    const TransformParam &transformParam,
    ApplicationInfo &applicationInfo)
{
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "transform ModuleJson to ApplicationInfo");
    auto app = moduleJson.app;
    applicationInfo.name = app.bundleName;
    applicationInfo.bundleName = app.bundleName;

    applicationInfo.versionCode = static_cast<uint32_t>(app.versionCode);
    applicationInfo.versionName = app.versionName;
    if (app.minCompatibleVersionCode != -1) {
        applicationInfo.minCompatibleVersionCode = app.minCompatibleVersionCode;
    } else {
        applicationInfo.minCompatibleVersionCode = static_cast<int32_t>(applicationInfo.versionCode);
    }

    applicationInfo.apiCompatibleVersion = app.minAPIVersion;
    applicationInfo.apiTargetVersion = app.targetAPIVersion;

    applicationInfo.iconPath = app.icon;
    applicationInfo.iconId = app.iconId;
    applicationInfo.label = app.label;
    applicationInfo.labelId = app.labelId;
    applicationInfo.description = app.description;
    applicationInfo.descriptionId = app.descriptionId;
    applicationInfo.iconResource = GetResource(app.bundleName, moduleJson.module.name, app.iconId);
    applicationInfo.labelResource = GetResource(app.bundleName, moduleJson.module.name, app.labelId);
    applicationInfo.descriptionResource = GetResource(app.bundleName, moduleJson.module.name, app.descriptionId);
    applicationInfo.targetBundleList = app.targetBundleList;

    if (transformParam.isSystemApp && transformParam.isPreInstallApp) {
        applicationInfo.keepAlive = app.keepAlive;
        applicationInfo.singleton = app.singleton;
        applicationInfo.userDataClearable = app.userDataClearable;
        if (app.removable.first) {
            applicationInfo.removable = app.removable.second;
        } else {
            applicationInfo.removable = false;
        }
        applicationInfo.accessible = app.accessible;
    }

    applicationInfo.apiReleaseType = app.apiReleaseType;
    applicationInfo.debug = app.debug;
    applicationInfo.deviceId = Constants::CURRENT_DEVICE_ID;
    applicationInfo.distributedNotificationEnabled = true;
    applicationInfo.entityType = Profile::APP_ENTITY_TYPE_DEFAULT_VALUE;
    applicationInfo.vendor = app.vendor;
    applicationInfo.asanEnabled = app.asanEnabled;
    if (app.bundleType == Profile::BUNDLE_TYPE_ATOMIC_SERVICE) {
        applicationInfo.bundleType = BundleType::ATOMIC_SERVICE;
    }

    applicationInfo.enabled = true;
    applicationInfo.multiProjects = app.multiProjects;
    applicationInfo.process = app.bundleName;
    applicationInfo.targetBundleName = app.targetBundle;
    applicationInfo.targetPriority = app.targetPriority;

    auto iterBundleType = std::find_if(std::begin(Profile::BUNDLE_TYPE_MAP),
        std::end(Profile::BUNDLE_TYPE_MAP),
        [&app](const auto &item) { return item.first == app.bundleType; });
    if (iterBundleType != Profile::BUNDLE_TYPE_MAP.end()) {
        applicationInfo.bundleType = iterBundleType->second;
    }
    applicationInfo.compileSdkVersion = app.compileSdkVersion;
    applicationInfo.compileSdkType = app.compileSdkType;
    return true;
}

uint32_t GetBackgroundModes(const std::vector<std::string> &backgroundModes)
{
    uint32_t backgroundMode = 0;
    for (const std::string &item : backgroundModes) {
        if (Profile::BACKGROUND_MODES_MAP.find(item) != Profile::BACKGROUND_MODES_MAP.end()) {
            backgroundMode |= Profile::BACKGROUND_MODES_MAP.at(item);
        }
    }
    return backgroundMode;
}

inline CompileMode ConvertCompileMode(const std::string& compileMode)
{
    if (compileMode == Profile::COMPILE_MODE_ES_MODULE) {
        return CompileMode::ES_MODULE;
    } else {
        return CompileMode::JS_BUNDLE;
    }
}

std::set<SupportWindowMode> ConvertToAbilityWindowMode(const std::vector<std::string> &windowModes,
    const std::unordered_map<std::string, SupportWindowMode> &windowMap)
{
    std::set<SupportWindowMode> modes;
    for_each(windowModes.begin(), windowModes.end(),
        [&windowMap, &modes](const auto &mode)->decltype(auto) {
        if (windowMap.find(mode) != windowMap.end()) {
            modes.emplace(windowMap.at(mode));
        }
    });
    if (modes.empty()) {
        modes.insert(SupportWindowMode::FULLSCREEN);
        modes.insert(SupportWindowMode::SPLIT);
        modes.insert(SupportWindowMode::FLOATING);
    }
    return modes;
}

bool ToAbilityInfo(
    const Profile::ModuleJson &moduleJson,
    const Profile::Ability &ability,
    const TransformParam &transformParam,
    AbilityInfo &abilityInfo)
{
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "transform ModuleJson to AbilityInfo");
    abilityInfo.name = ability.name;
    abilityInfo.srcEntrance = ability.srcEntrance;
    abilityInfo.description = ability.description;
    abilityInfo.descriptionId = ability.descriptionId;
    abilityInfo.iconPath = ability.icon;
    abilityInfo.iconId = ability.iconId;
    abilityInfo.label = ability.label;
    abilityInfo.labelId = ability.labelId;
    abilityInfo.priority = ability.priority;
    abilityInfo.excludeFromMissions = ability.excludeFromMissions;
    abilityInfo.unclearableMission = ability.unclearableMission;
    abilityInfo.recoverable = ability.recoverable;
    abilityInfo.permissions = ability.permissions;
    abilityInfo.visible = ability.visible;
    abilityInfo.continuable = ability.continuable;
    abilityInfo.backgroundModes = GetBackgroundModes(ability.backgroundModes);
    GetMetadata(abilityInfo.metadata, ability.metadata);
    abilityInfo.package = moduleJson.module.name;
    abilityInfo.bundleName = moduleJson.app.bundleName;
    abilityInfo.moduleName = moduleJson.module.name;
    abilityInfo.applicationName = moduleJson.app.bundleName;
    auto iterLaunch = std::find_if(std::begin(Profile::LAUNCH_MODE_MAP),
        std::end(Profile::LAUNCH_MODE_MAP),
        [&ability](const auto &item) { return item.first == ability.launchType; });
    if (iterLaunch != Profile::LAUNCH_MODE_MAP.end()) {
        abilityInfo.launchMode = iterLaunch->second;
    }
    abilityInfo.enabled = true;
    abilityInfo.isModuleJson = true;
    abilityInfo.isStageBasedModel = true;
    abilityInfo.type = AbilityType::PAGE;
    for (const std::string &deviceType : moduleJson.module.deviceTypes) {
        abilityInfo.deviceTypes.emplace_back(deviceType);
    }
    abilityInfo.startWindowIcon = ability.startWindowIcon;
    abilityInfo.startWindowIconId = ability.startWindowIconId;
    abilityInfo.startWindowBackground = ability.startWindowBackground;
    abilityInfo.startWindowBackgroundId = ability.startWindowBackgroundId;
    abilityInfo.removeMissionAfterTerminate = ability.removeMissionAfterTerminate;
    abilityInfo.compileMode = ConvertCompileMode(moduleJson.module.compileMode);
    auto iterOrientation = std::find_if(std::begin(Profile::DISPLAY_ORIENTATION_MAP),
        std::end(Profile::DISPLAY_ORIENTATION_MAP),
        [&ability](const auto &item) { return item.first == ability.orientation; });
    if (iterOrientation != Profile::DISPLAY_ORIENTATION_MAP.end()) {
        abilityInfo.orientation = iterOrientation->second;
    }

    auto modesSet = ConvertToAbilityWindowMode(ability.windowModes, Profile::WINDOW_MODE_MAP);
    abilityInfo.windowModes.assign(modesSet.begin(), modesSet.end());
    abilityInfo.maxWindowRatio = ability.maxWindowRatio;
    abilityInfo.minWindowRatio = ability.minWindowRatio;
    abilityInfo.maxWindowWidth = ability.maxWindowWidth;
    abilityInfo.minWindowWidth = ability.minWindowWidth;
    abilityInfo.maxWindowHeight = ability.maxWindowHeight;
    abilityInfo.minWindowHeight = ability.minWindowHeight;
    return true;
}

bool ToExtensionInfo(
    const Profile::ModuleJson &moduleJson,
    const Profile::Extension &extension,
    const TransformParam &transformParam,
    ExtensionAbilityInfo &extensionInfo)
{
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "transform ModuleJson to ExtensionAbilityInfo");
    extensionInfo.type = ConvertToExtensionAbilityType(extension.type);
    extensionInfo.name = extension.name;
    extensionInfo.srcEntrance = extension.srcEntrance;
    extensionInfo.icon = extension.icon;
    extensionInfo.iconId = extension.iconId;
    extensionInfo.label = extension.label;
    extensionInfo.labelId = extension.labelId;
    extensionInfo.description = extension.description;
    extensionInfo.descriptionId = extension.descriptionId;
    if (transformParam.isSystemApp && transformParam.isPreInstallApp) {
        extensionInfo.readPermission = extension.readPermission;
        extensionInfo.writePermission = extension.writePermission;
    }
    extensionInfo.priority = extension.priority;
    extensionInfo.uri = extension.uri;
    extensionInfo.permissions = extension.permissions;
    extensionInfo.visible = extension.visible;
    GetMetadata(extensionInfo.metadata, extension.metadata);
    extensionInfo.bundleName = moduleJson.app.bundleName;
    extensionInfo.moduleName = moduleJson.module.name;

    if (extensionInfo.type != ExtensionAbilityType::SERVICE &&
        extensionInfo.type != ExtensionAbilityType::DATASHARE) {
        extensionInfo.process = extensionInfo.bundleName;
        extensionInfo.process.append(":");
        extensionInfo.process.append(ConvertToExtensionTypeName(extensionInfo.type));
    }

    extensionInfo.compileMode = ConvertCompileMode(moduleJson.module.compileMode);

    return true;
}

bool ToInnerModuleInfo(
    const Profile::ModuleJson &moduleJson,
    const TransformParam &transformParam,
    InnerModuleInfo &innerModuleInfo)
{
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "transform ModuleJson to InnerModuleInfo");
    innerModuleInfo.name = moduleJson.module.name;
    innerModuleInfo.modulePackage = moduleJson.module.name;
    innerModuleInfo.moduleName = moduleJson.module.name;
    innerModuleInfo.description = moduleJson.module.description;
    innerModuleInfo.descriptionId = moduleJson.module.descriptionId;
    GetMetadata(innerModuleInfo.metadata, moduleJson.module.metadata);
    innerModuleInfo.distro.deliveryWithInstall = moduleJson.module.deliveryWithInstall;
    innerModuleInfo.distro.installationFree = moduleJson.module.installationFree;
    innerModuleInfo.distro.moduleName = moduleJson.module.name;
    innerModuleInfo.installationFree = moduleJson.module.installationFree;
    if (Profile::MODULE_TYPE_SET.find(moduleJson.module.type) != Profile::MODULE_TYPE_SET.end()) {
        innerModuleInfo.distro.moduleType = moduleJson.module.type;
        if (moduleJson.module.type == Profile::MODULE_TYPE_ENTRY) {
            innerModuleInfo.isEntry = true;
        }
    }

    innerModuleInfo.mainAbility = moduleJson.module.mainElement;
    innerModuleInfo.srcEntrance = moduleJson.module.srcEntrance;
    innerModuleInfo.process = moduleJson.module.process;

    for (const std::string &deviceType : moduleJson.module.deviceTypes) {
        innerModuleInfo.deviceTypes.emplace_back(deviceType);
    }

    if (Profile::VIRTUAL_MACHINE_SET.find(moduleJson.module.virtualMachine) != Profile::VIRTUAL_MACHINE_SET.end()) {
        innerModuleInfo.virtualMachine = moduleJson.module.virtualMachine;
    }

    innerModuleInfo.uiSyntax = Profile::MODULE_UI_SYNTAX_DEFAULT_VALUE;
    innerModuleInfo.pages = moduleJson.module.pages;
    innerModuleInfo.dependencies = moduleJson.module.dependencies;
    innerModuleInfo.compileMode = moduleJson.module.compileMode;
    innerModuleInfo.isModuleJson = true;
    innerModuleInfo.isStageBasedModel = true;
    innerModuleInfo.isLibIsolated = moduleJson.module.isLibIsolated;
    innerModuleInfo.targetModuleName = moduleJson.module.targetModule;
    innerModuleInfo.targetPriority = moduleJson.module.targetPriority;
    if (moduleJson.module.proxyDatas.empty()) {
        innerModuleInfo.proxyDatas = moduleJson.module.proxyData;
    } else {
        innerModuleInfo.proxyDatas = moduleJson.module.proxyDatas;
    }
    innerModuleInfo.buildHash = moduleJson.module.buildHash;
    innerModuleInfo.isolationMode = moduleJson.module.isolationMode;
    return true;
}

void SetInstallationFree(InnerModuleInfo &innerModuleInfo, BundleType bundleType)
{
    if (bundleType == BundleType::ATOMIC_SERVICE) {
        innerModuleInfo.distro.installationFree = true;
        innerModuleInfo.installationFree = true;
    } else {
        innerModuleInfo.distro.installationFree = false;
        innerModuleInfo.installationFree = false;
    }
}

void ToBundleInfo(const ApplicationInfo &applicationInfo, const InnerModuleInfo &innerModuleInfo,
    const TransformParam &transformParam, BundleInfo &bundleInfo)
{
    bundleInfo.name = applicationInfo.bundleName;

    bundleInfo.versionCode = static_cast<uint32_t>(applicationInfo.versionCode);
    bundleInfo.versionName = applicationInfo.versionName;
    bundleInfo.minCompatibleVersionCode = static_cast<uint32_t>(applicationInfo.minCompatibleVersionCode);

    bundleInfo.compatibleVersion = static_cast<uint32_t>(applicationInfo.apiCompatibleVersion);
    bundleInfo.targetVersion = static_cast<uint32_t>(applicationInfo.apiTargetVersion);

    bundleInfo.isKeepAlive = applicationInfo.keepAlive;
    bundleInfo.singleton = applicationInfo.singleton;
    bundleInfo.isPreInstallApp = transformParam.isPreInstallApp;

    bundleInfo.vendor = applicationInfo.vendor;
    bundleInfo.releaseType = applicationInfo.apiReleaseType;
    bundleInfo.isNativeApp = false;

    if (innerModuleInfo.isEntry) {
        bundleInfo.mainEntry = innerModuleInfo.moduleName;
        bundleInfo.entryModuleName = innerModuleInfo.moduleName;
    }
}

bool ParseExtensionInfo(const Profile::ModuleJson &moduleJson, InnerBundleInfo &innerBundleInfo,
    const TransformParam &transformParam, InnerModuleInfo &innerModuleInfo)
{
    for (const Profile::Extension &extension : moduleJson.module.extensionAbilities) {
        ExtensionAbilityInfo extensionInfo;
        if (!ToExtensionInfo(moduleJson, extension, transformParam, extensionInfo)) {
            TAG_LOGE(AAFwkTag::ABILITY_SIM, "extensionInfo failed");
            return false;
        }

        if (innerModuleInfo.mainAbility == extensionInfo.name) {
            innerModuleInfo.icon = extensionInfo.icon;
            innerModuleInfo.iconId = extensionInfo.iconId;
            innerModuleInfo.label = extensionInfo.label;
            innerModuleInfo.labelId = extensionInfo.labelId;
        }

        std::string key;
        key.append(moduleJson.app.bundleName).append(".")
            .append(moduleJson.module.name).append(".").append(extension.name);
        innerModuleInfo.extensionKeys.emplace_back(key);
        innerBundleInfo.InsertExtensionInfo(key, extensionInfo);
    }
    return true;
}

bool ToInnerBundleInfo(const Profile::ModuleJson &moduleJson, InnerBundleInfo &innerBundleInfo)
{
    if (!CheckBundleNameIsValid(moduleJson.app.bundleName) || !CheckModuleNameIsValid(moduleJson.module.name)) {
        return false;
    }
    TransformParam transformParam;
    ApplicationInfo applicationInfo;
    applicationInfo.isSystemApp = innerBundleInfo.GetAppType() == Constants::AppType::SYSTEM_APP;
    transformParam.isSystemApp = applicationInfo.isSystemApp;
    if (!ToApplicationInfo(moduleJson, transformParam, applicationInfo)) {
        return false;
    }
    InnerModuleInfo innerModuleInfo;
    ToInnerModuleInfo(moduleJson, transformParam, innerModuleInfo);
    SetInstallationFree(innerModuleInfo, applicationInfo.bundleType);

    BundleInfo bundleInfo;
    ToBundleInfo(applicationInfo, innerModuleInfo, transformParam, bundleInfo);

    for (const Profile::Ability &ability : moduleJson.module.abilities) {
        AbilityInfo abilityInfo;
        ToAbilityInfo(moduleJson, ability, transformParam, abilityInfo);
        if (innerModuleInfo.mainAbility == abilityInfo.name) {
            innerModuleInfo.icon = abilityInfo.iconPath;
            innerModuleInfo.iconId = abilityInfo.iconId;
            innerModuleInfo.label = abilityInfo.label;
            innerModuleInfo.labelId = abilityInfo.labelId;
        }
        std::string key;
        key.append(moduleJson.app.bundleName).append(".")
            .append(moduleJson.module.name).append(".").append(abilityInfo.name);
        innerModuleInfo.abilityKeys.emplace_back(key);
        innerBundleInfo.InsertAbilitiesInfo(key, abilityInfo);
    }
    if (!ParseExtensionInfo(moduleJson, innerBundleInfo, transformParam, innerModuleInfo)) {
        return false;
    }
    if (!transformParam.isPreInstallApp &&
        innerModuleInfo.distro.moduleType != Profile::MODULE_TYPE_SHARED) {
        applicationInfo.needAppDetail = true;
        applicationInfo.appDetailAbilityLibraryPath = Profile::APP_DETAIL_ABILITY_LIBRARY_PATH;
        if ((applicationInfo.labelId == 0) && (applicationInfo.label.empty())) {
            applicationInfo.label = applicationInfo.bundleName;
        }
    }
    innerBundleInfo.SetCurrentModulePackage(moduleJson.module.name);
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    innerBundleInfo.InsertInnerModuleInfo(moduleJson.module.name, innerModuleInfo);
    innerBundleInfo.SetTargetPriority(moduleJson.app.targetPriority);
    return true;
}

bool ParseAtomicServicePreloads(const cJSON *jsonObject, std::vector<std::string> &preloads)
{
    if (!cJSON_IsArray(jsonObject)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "jsonObject not array");
        return false;
    }
    int size = cJSON_GetArraySize(jsonObject);
    if (size == 0) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "jsonObject is empty");
        return true;
    }
    if (size > Constants::MAX_JSON_ARRAY_LENGTH) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "preloads config in module.json is oversize");
        return false;
    }
    for (int i = 0; i < size; i++) {
        cJSON *preloadItem = cJSON_GetArrayItem(jsonObject, i);
        if (preloadItem == nullptr) {
            TAG_LOGE(AAFwkTag::ABILITY_SIM, "preloads is null");
            return false;
        }
        cJSON *preloadsModuleNameItem = cJSON_GetObjectItem(preloadItem, Profile::PRELOADS_MODULE_NAME);
        if (preloadsModuleNameItem == nullptr) {
            TAG_LOGE(AAFwkTag::ABILITY_SIM, "preloads must have moduleName");
            return false;
        }
        std::string preloadName = preloadsModuleNameItem->valuestring;
        preloads.emplace_back(preloadName);
    }
    return true;
}

bool ParserAtomicModuleConfig(const cJSON *jsonObject, InnerBundleInfo &innerBundleInfo)
{
    cJSON *moduleJson = cJSON_GetObjectItem(jsonObject, Profile::MODULE);
    if (moduleJson == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "get module json failed");
        return false;
    }
    cJSON *moduleNameItem = cJSON_GetObjectItem(moduleJson, Profile::MODULE_NAME);
    if (moduleNameItem == nullptr || !cJSON_IsString(moduleNameItem)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "get module name failed");
        return false;
    }
    std::string moduleName = moduleNameItem->valuestring;
    std::vector<std::string> preloads;
    cJSON *moduleAtomicObj = cJSON_GetObjectItem(moduleJson, Profile::ATOMIC_SERVICE);
    if (moduleAtomicObj != nullptr) {
        cJSON *preloadObj = cJSON_GetObjectItem(moduleAtomicObj, Profile::MODULE_ATOMIC_SERVICE_PRELOADS);
        if (preloadObj != nullptr) {
            if (!ParseAtomicServicePreloads(preloadObj, preloads)) {
                TAG_LOGE(AAFwkTag::ABILITY_SIM, "reloadObj not array");
                return false;
            }
        }
    }
    innerBundleInfo.SetInnerModuleAtomicPreload(moduleName, preloads);
    return true;
}

bool ParserAtomicConfig(const cJSON *jsonObject, InnerBundleInfo &innerBundleInfo)
{
    cJSON *moduleJson = cJSON_GetObjectItem(jsonObject, Profile::MODULE);
    cJSON *appJson = cJSON_GetObjectItem(jsonObject, Profile::APP);
    if (moduleJson == nullptr || appJson == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "ParserAtomicConfig failed due to bad module.json");
        return false;
    }

    if (!cJSON_IsObject(moduleJson) || !cJSON_IsObject(appJson)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "module.json file lacks of invalid module or app properties");
        return false;
    }
    BundleType bundleType = BundleType::APP;
    cJSON *bundleTypeItem = cJSON_GetObjectItem(appJson, Profile::BUNDLE_TYPE);
    if (bundleTypeItem != nullptr && cJSON_IsString(bundleTypeItem)) {
        std::string type = bundleTypeItem->valuestring;
        if (type == Profile::BUNDLE_TYPE_ATOMIC_SERVICE) {
            bundleType = BundleType::ATOMIC_SERVICE;
        } else if (type == Profile::BUNDLE_TYPE_SHARED) {
            bundleType = BundleType::SHARED;
        } else if (type == Profile::BUNDLE_TYPE_APP_SERVICE_FWK) {
            bundleType = BundleType::APP_SERVICE_FWK;
        } else if (type == Profile::BUNDLE_TYPE_PLUGIN) {
            bundleType = BundleType::APP_PLUGIN;
        }
    }

    innerBundleInfo.SetApplicationBundleType(bundleType);
    if (!ParserAtomicModuleConfig(jsonObject, innerBundleInfo)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "parse module atomicService failed");
        return false;
    }
    return true;
}
} // namespace

ErrCode ModuleProfile::TransformTo(const std::vector<uint8_t> &buf, InnerBundleInfo &innerBundleInfo) const
{
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "transform module.json stream to InnerBundleInfo");
    std::vector<uint8_t> buffer = buf;
    buffer.push_back('\0');
    std::string dataStr(buffer.begin(), buffer.end());
    cJSON *jsonObject = cJSON_Parse(dataStr.c_str());
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "bad profile");
        return ERR_APPEXECFWK_PARSE_BAD_PROFILE;
    }

    Profile::ModuleJson moduleJson;
    from_json(jsonObject, moduleJson);
    cJSON_Delete(jsonObject);
    if (Profile::g_parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "g_parseResult:%{public}d", Profile::g_parseResult);
        int32_t ret = Profile::g_parseResult;
        // need recover parse result to ERR_OK
        Profile::g_parseResult = ERR_OK;
        return ret;
    }

    if (!ToInnerBundleInfo(moduleJson, innerBundleInfo)) {
        return ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR;
    }

    if (!ParserAtomicConfig(jsonObject, innerBundleInfo)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "Parser atomicService config failed");
        return ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR;
    }

    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
