/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_ABILITY_RUNTIME_SIMULATOR_COMMON_APPLICATION_INFO_H
#define FOUNDATION_ABILITY_RUNTIME_SIMULATOR_COMMON_APPLICATION_INFO_H

#include <map>
#include <string>
#include <vector>
#include "module_info.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
static const std::string AVAILABLELEVEL_NORMAL = "normal";
static const std::string DEFAULT_ENTITY_TYPE = "unspecified";
static const std::string DEFAULT_COMPILE_SDK_TYPE = "OpenHarmony";
}
enum ApplicationFlag {
    GET_BASIC_APPLICATION_INFO = 0x00000000,
    GET_APPLICATION_INFO_WITH_PERMISSION = 0x00000008,
    GET_APPLICATION_INFO_WITH_METADATA = 0x00000040,
    GET_APPLICATION_INFO_WITH_DISABLE = 0x00000200,
    GET_APPLICATION_INFO_WITH_CERTIFICATE_FINGERPRINT = 0x00000400,
    GET_ALL_APPLICATION_INFO = 0xFFFF0000,
};

enum class GetApplicationFlag {
    GET_APPLICATION_INFO_DEFAULT = 0x00000000,
    GET_APPLICATION_INFO_WITH_PERMISSION = 0x00000001,
    GET_APPLICATION_INFO_WITH_METADATA = 0x00000002,
    GET_APPLICATION_INFO_WITH_DISABLE = 0x00000004,
};

enum class GetDependentBundleInfoFlag {
    GET_APP_CROSS_HSP_BUNDLE_INFO = 0x00000000,
    GET_APP_SERVICE_HSP_BUNDLE_INFO = 0x00000001,
    GET_ALL_DEPENDENT_BUNDLE_INFO = 0x00000002,
};

enum class BundleType {
    APP = 0,
    ATOMIC_SERVICE = 1,
    SHARED = 2,
    APP_SERVICE_FWK = 3,
    APP_PLUGIN = 4,
};

enum class CompatiblePolicy {
    NORMAL = 0,
    BACKWARD_COMPATIBILITY = 1,
};

enum class ApplicationReservedFlag {
    ENCRYPTED_APPLICATION = 0x00000001,
    ENCRYPTED_KEY_EXISTED = 0x00000002,
};

enum class MultiAppModeType : uint8_t {
    UNSPECIFIED = 0,
    MULTI_INSTANCE = 1,
    APP_CLONE = 2,
};

enum class ApplicationInfoFlag {
    FLAG_INSTALLED = 0x00000001,
    /**
     * Indicates the installation source of pre-installed applications
     * App upgrades will not change installation source
     * FLAG_BOOT_INSTALLED App installed during first boot
     * FLAG_OTA_INSTALLED App installed during OTA
     * FLAG_RECOVER_INSTALLED App recover
     */
    FLAG_BOOT_INSTALLED = 0x00000002,
    FLAG_OTA_INSTALLED = 0x00000004,
    FLAG_RECOVER_INSTALLED = 0x00000008,
    FLAG_OTHER_INSTALLED = 0x00000010,
    FLAG_PREINSTALLED_APP = 0x00000020,
    FLAG_PREINSTALLED_APP_UPDATE = 0x00000040,
};

enum class QuickFixType : int8_t {
    UNKNOWN = 0,
    PATCH = 1,
    HOT_RELOAD = 2
};

struct Metadata {
    uint32_t valueId = 0;
    std::string name;
    std::string value;
    std::string resource;
};

struct HnpPackage {
    std::string package;
    std::string type;
};

struct CustomizeData {
    std::string name;
    std::string value;
    std::string extra;
};

struct MetaData {
    std::vector<CustomizeData> customizeData;
};

struct Resource {
    /** the hap bundle name */
    std::string bundleName;

    /** the hap module name */
    std::string moduleName;

    /** the resource id in hap */
    int32_t id = 0;
};

struct MultiAppModeData {
    MultiAppModeType multiAppModeType = MultiAppModeType::UNSPECIFIED;
    int32_t maxCount = 0;
};

struct ApplicationEnvironment {
    std::string name;
    std::string value;
};

struct HqfInfo {
    QuickFixType type = QuickFixType::UNKNOWN; // quick fix type
    std::string moduleName;
    std::string hapSha256;
    std::string hqfFilePath;
    std::string cpuAbi;
    std::string nativeLibraryPath;
};

struct AppqfInfo {
    QuickFixType type = QuickFixType::UNKNOWN; // quick fix type
    uint32_t versionCode = 0; // quick fix version code
    std::string versionName; // quick fix version name
    std::string cpuAbi; // quick fix abi
    std::string nativeLibraryPath; // quick fix so path
    std::vector<HqfInfo> hqfInfos;
};

struct AppQuickFix {
    uint32_t versionCode = 0; // original bundle version code
    std::string bundleName; // original bundle name
    std::string versionName; // original bundle version name

    AppqfInfo deployedAppqfInfo; // deployed quick fix patch
    AppqfInfo deployingAppqfInfo; // deploying quick fix patch
};

// configuration information about an application
struct ApplicationInfo {
    std::string name;  // application name is same to bundleName
    std::string bundleName;

    uint32_t versionCode = 0;
    std::string versionName;
    int32_t minCompatibleVersionCode = 0;

    uint32_t apiCompatibleVersion = 0;
    int32_t apiTargetVersion = 0;
    int64_t crowdtestDeadline = -1;

    std::string iconPath;
    int32_t iconId = 0;
    Resource iconResource;

    std::string label;
    int32_t labelId = 0;
    Resource labelResource;

    std::string description;
    int32_t descriptionId = 0;
    Resource descriptionResource;

    bool keepAlive = false;
    bool removable = true;
    bool singleton = false;
    bool userDataClearable = true;
    bool allowAppRunWhenDeviceFirstLocked = false;
    bool accessible = false;
    bool runningResourcesApply = false;
    bool associatedWakeUp = false;
    bool hideDesktopIcon = false;
    bool formVisibleNotify = false;
    bool installedForAllUser = false;
    bool allowEnableNotification = false;
    bool allowMultiProcess = false;
    bool gwpAsanEnabled = false;
    bool hasPlugin = false;
    std::vector<std::string> allowCommonEvent;
    std::vector<std::string> assetAccessGroups;
    std::vector<int32_t> resourcesApply;

    bool isSystemApp = false;
    bool isLauncherApp = false;
    bool isFreeInstallApp = false;
    bool asanEnabled = false;
    std::string asanLogPath;

    std::string codePath;
    std::string dataDir;
    std::string dataBaseDir;
    std::string cacheDir;
    std::string entryDir;

    std::string apiReleaseType;
    bool debug = false;
    std::string deviceId;
    bool distributedNotificationEnabled = true;
    std::string entityType = DEFAULT_ENTITY_TYPE;
    std::string process;
    int32_t supportedModes = 0;  // returns 0 if the application does not support the driving mode
    std::string vendor;

    // apl
    std::string appPrivilegeLevel = AVAILABLELEVEL_NORMAL;
    std::string appDistributionType = "none";
    std::string appProvisionType = "release";

    // user related fields, assign when calling the get interface
    uint32_t accessTokenId = 0;
    uint32_t applicationReservedFlag = 0;
    uint64_t accessTokenIdEx = 0;
    bool enabled = false;
    int32_t appIndex = 0;
    int32_t uid = -1;
    int32_t maxChildProcess = 0;
    int32_t applicationFlags = static_cast<uint32_t>(ApplicationInfoFlag::FLAG_INSTALLED);
    MultiAppModeData multiAppMode;

    // native so
    std::string nativeLibraryPath;
    std::string cpuAbi;
    std::string arkNativeFilePath;
    std::string arkNativeFileAbi;

    // assign when calling the get interface
    std::vector<std::string> permissions;
    std::vector<std::string> moduleSourceDirs;
    std::vector<ModuleInfo> moduleInfos;
    std::map<std::string, std::vector<CustomizeData>> metaData;
    std::map<std::string, std::vector<Metadata>> metadata;
    // Installation-free
    std::vector<std::string> targetBundleList;

    std::vector<ApplicationEnvironment> appEnvironments;
    std::map<std::string, std::vector<HnpPackage>> hnpPackages;
    std::string fingerprint;

    // quick fix info
    AppQuickFix appQuickFix;

    // unused
    std::string icon;
    int32_t flags = 0;
    std::string entryModuleName;
    bool isCompressNativeLibs = true;
    std::string signatureKey;

    // switch
    bool multiProjects = false;
    bool tsanEnabled = false;
    bool hwasanEnabled = false;
    bool ubsanEnabled = false;
    bool cloudFileSyncEnabled = false;

    // app detail ability
    bool needAppDetail = false;
    std::string appDetailAbilityLibraryPath;

    // overlay installation
    std::string targetBundleName;
    int32_t targetPriority;
    int32_t overlayState = 0;
    bool split = true;
    BundleType bundleType = BundleType::APP;

    std::string compileSdkVersion;
    std::string compileSdkType = DEFAULT_COMPILE_SDK_TYPE;
    std::string organization;
    std::string installSource;
    std::string configuration;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_ABILITY_RUNTIME_SIMULATOR_COMMON_APPLICATION_INFO_H
