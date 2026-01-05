/*
* Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#ifndef ABILITY_FUZZ_UTIL_H
#define ABILITY_FUZZ_UTIL_H

#include <fuzzer/FuzzedDataProvider.h>
#include <map>
#include <string>
#include <vector>

#include "ability_record.h"
#include "ability_info.h"
#include "application_info.h"
#include "auto_startup_info.h"
#include "bundle_info.h"
#include "bundle_user_info.h"
#include "dlp_connection_info.h"
#include "dlp_state_data.h"
#include "ecological_rule/ability_ecological_rule_mgr_service_param.h"
#include "extract_insight_intent_profile.h"
#include "keep_alive_info.h"
#include "keep_alive_process_manager.h"

namespace OHOS {
namespace AppExecFwk {
namespace AbilityFuzzUtil {
constexpr size_t CODE_TWO = 2;
constexpr size_t CODE_FOUR = 4;
constexpr size_t CODE_TEN = 10;
constexpr size_t CODE_MAX = 99;
constexpr size_t STRING_MAX_LENGTH = 128;
constexpr uint32_t CODE_MIN_ONE = 1;
constexpr uint32_t CODE_MAX_THREE = 3;

std::vector<std::string> GenerateStringArray(FuzzedDataProvider& fdp, size_t arraySizeMax = STRING_MAX_LENGTH,
    size_t stringSize = STRING_MAX_LENGTH)
{
    std::vector<std::string> result;
    size_t arraySize = fdp.ConsumeIntegralInRange<size_t>(0, arraySizeMax);
    result.reserve(arraySize);

    for (size_t i = 0; i < arraySize; ++i) {
        std::string str = fdp.ConsumeRandomLengthString(stringSize);
        result.emplace_back(str);
    }

    return result;
}

AppExecFwk::ElementName GenerateElementName(FuzzedDataProvider& fdp, AppExecFwk::ElementName &elementName)
{
    std::string deviceId;
    std::string bundleName;
    std::string abilityName;
    std::string moduleName;
    deviceId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    AppExecFwk::ElementName name(deviceId, bundleName, abilityName, moduleName);

    return name;
}

void GetRandomExtractInsightIntentGenericInfo(FuzzedDataProvider& fdp, ExtractInsightIntentGenericInfo& info)
{
    info.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.intentName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.displayName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.decoratorType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}

void GetRandomInsightIntentInfoForQuery(FuzzedDataProvider& fdp, InsightIntentInfoForQuery& info)
{
    info.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.intentName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.domain = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.intentVersion = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.displayName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.displayDescription = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.schema = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.icon = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.llmDescription = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.intentType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.parameters = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.result = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.keywords = GenerateStringArray(fdp);
}

void GetRandomExtractInsightIntentInfo(FuzzedDataProvider& fdp, ExtractInsightIntentInfo& info)
{
    info.decoratorFile = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.decoratorClass = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.displayDescription = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.domain = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.intentVersion = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.schema = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.icon = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.llmDescription = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.result = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.example = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.keywords = GenerateStringArray(fdp);
}

void GetRandomInsightIntentExecuteParam(FuzzedDataProvider& fdp, InsightIntentExecuteParam& info)
{
    info.executeMode_ = fdp.ConsumeIntegral<int32_t>();
    info.displayId_ = fdp.ConsumeIntegral<int32_t>();
    info.flags_ = fdp.ConsumeIntegral<int32_t>();
    info.insightIntentId_ = fdp.ConsumeIntegral<uint64_t>();
    info.bundleName_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.moduleName_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.abilityName_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.insightIntentName_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.uris_ = GenerateStringArray(fdp);
    info.decoratorType_ = fdp.ConsumeIntegral<int8_t>();
    info.srcEntrance_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.className_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.methodName_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.methodParams_ = GenerateStringArray(fdp);
    info.pagePath_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.navigationId_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.navDestinationName_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}

void GetRandomExtractInsightIntentProfileInfo(FuzzedDataProvider& fdp, ExtractInsightIntentProfileInfo& info)
{
    info.decoratorFile = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.decoratorClass = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.decoratorType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.intentName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.domain = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.intentVersion = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.displayName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.displayDescription = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.schema = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.icon = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.llmDescription = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.keywords = GenerateStringArray(fdp);
    info.parameters = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.result = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.example = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.uri = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.uiAbility = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.pagePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.navigationId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.navDestinationName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.abilityName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.executeMode = GenerateStringArray(fdp);
    info.functionName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.functionParams = GenerateStringArray(fdp);
    info.formName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}

void GetRandomKeepAliveStatus(FuzzedDataProvider& fdp, KeepAliveStatus& status)
{
    status.code = fdp.ConsumeIntegral<int32_t>();
    status.setterId = fdp.ConsumeIntegral<int32_t>();
    status.setter = static_cast<KeepAliveSetter>(fdp.ConsumeIntegralInRange<int32_t>(0, CODE_TWO));
}

void GetRandomDlpConnectionInfo(FuzzedDataProvider& fdp, DlpConnectionInfo& info)
{
    info.dlpUid = fdp.ConsumeIntegral<int32_t>();
    info.openedAbilityCount = fdp.ConsumeIntegral<int32_t>();
}

void GetRandomConnectionData(FuzzedDataProvider& fdp, ConnectionData& info)
{
    info.isSuspended = fdp.ConsumeBool();
    info.extensionPid = fdp.ConsumeIntegral<uint32_t>();
    info.extensionUid = fdp.ConsumeIntegral<uint32_t>();
    info.callerUid = fdp.ConsumeIntegral<uint32_t>();
    info.callerPid = fdp.ConsumeIntegral<uint32_t>();
    info.extensionBundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.extensionModuleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.extensionName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.callerName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}

void GetRandomDlpStateData(FuzzedDataProvider& fdp, DlpStateData& info)
{
    info.targetPid = fdp.ConsumeIntegral<uint32_t>();
    info.targetUid = fdp.ConsumeIntegral<uint32_t>();
    info.callerUid = fdp.ConsumeIntegral<uint32_t>();
    info.callerPid = fdp.ConsumeIntegral<uint32_t>();
    info.callerName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.targetBundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.targetModuleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.targetAbilityName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}

void GenerateSignatureInfo(FuzzedDataProvider& fdp, SignatureInfo &signatureInfo)
{
    signatureInfo.appId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    signatureInfo.fingerprint = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    signatureInfo.appIdentifier = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    signatureInfo.certificate = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}

void GetRandomAbilityInfo(FuzzedDataProvider& fdp, AbilityInfo& info)
{
    info.name = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.label = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.description = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.iconPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.labelId = fdp.ConsumeIntegral<int32_t>();
    info.descriptionId = fdp.ConsumeIntegral<int32_t>();
    info.iconId = fdp.ConsumeIntegral<int32_t>();
    info.theme = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.visible = fdp.ConsumeBool();
    info.kind = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}

void GetRandomAbilityExperienceRule(FuzzedDataProvider& fdp, AbilityExperienceRule& rule)
{
    rule.resultCode = fdp.ConsumeIntegral<int32_t>();
    rule.sceneCode = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    rule.isBackSkuExempt = fdp.ConsumeBool();
    rule.embedResultCode = fdp.ConsumeIntegral<int32_t>();
}

void GetRandomAutoStartupInfo(FuzzedDataProvider& fdp, AutoStartupInfo& info)
{
    info.appCloneIndex = fdp.ConsumeIntegral<int32_t>();
    info.userId = fdp.ConsumeIntegral<int32_t>();
    info.retryCount = fdp.ConsumeIntegral<int32_t>();
    info.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.abilityName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.abilityTypeName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.accessTokenId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}

void GetRandomBundleInfo(FuzzedDataProvider& fdp, BundleInfo& info)
{
    info.isNewVersion = fdp.ConsumeBool();
    info.isKeepAlive = fdp.ConsumeBool();
    info.singleton = fdp.ConsumeBool();
    info.isPreInstallApp = fdp.ConsumeBool();
    info.isNativeApp = fdp.ConsumeBool();
    info.entryInstallationFree = fdp.ConsumeBool();
    info.isDifferentName = fdp.ConsumeBool();
    info.versionCode = fdp.ConsumeIntegral<uint32_t>();
    info.minCompatibleVersionCode = fdp.ConsumeIntegral<uint32_t>();
    info.compatibleVersion = fdp.ConsumeIntegral<uint32_t>();
    info.targetVersion = fdp.ConsumeIntegral<uint32_t>();
    info.appIndex = fdp.ConsumeIntegral<int32_t>();
    info.minSdkVersion = fdp.ConsumeIntegral<int32_t>();
    info.maxSdkVersion = fdp.ConsumeIntegral<int32_t>();
    info.overlayType = fdp.ConsumeIntegral<int32_t>();
    info.installTime = fdp.ConsumeIntegral<int64_t>();
    info.updateTime = fdp.ConsumeIntegral<int64_t>();
    info.firstInstallTime = fdp.ConsumeIntegral<int64_t>();
    info.name = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.versionName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.vendor = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.releaseType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.mainEntry = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.entryModuleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.appId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.cpuAbi = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.seInfo = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.label = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.description = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.jointUserId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    GenerateSignatureInfo(fdp, info.signatureInfo);
    info.oldAppIds = GenerateStringArray(fdp);
    info.hapModuleNames = GenerateStringArray(fdp);
    info.moduleNames = GenerateStringArray(fdp);
    info.modulePublicDirs = GenerateStringArray(fdp);
    info.moduleDirs = GenerateStringArray(fdp);
    info.moduleResPaths = GenerateStringArray(fdp);
    info.reqPermissions = GenerateStringArray(fdp);
    info.defPermissions = GenerateStringArray(fdp);
}

void GetRandomKeepAliveInfo(FuzzedDataProvider& fdp, KeepAliveInfo& info)
{
    info.userId = fdp.ConsumeIntegral<int32_t>();
    info.setterId = fdp.ConsumeIntegral<int32_t>();
    info.appType = static_cast<KeepAliveAppType>(fdp.ConsumeIntegralInRange<int32_t>(0, CODE_TWO));
    info.setter = static_cast<KeepAliveSetter>(fdp.ConsumeIntegralInRange<int32_t>(0, CODE_TWO));
    info.policy = static_cast<KeepAlivePolicy>(fdp.ConsumeIntegralInRange<int32_t>(0, CODE_TWO));
    info.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}

void GetRandomKeepAliveAbilityInfo(FuzzedDataProvider& fdp, KeepAliveAbilityInfo& info)
{
    info.userId = fdp.ConsumeIntegral<int32_t>();
    info.appCloneIndex = fdp.ConsumeIntegral<int32_t>();
    info.uid = fdp.ConsumeIntegral<int32_t>();
    info.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.abilityName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}

void GetRandomKeepAliveAppInfo(FuzzedDataProvider& fdp, AppInfo& info)
{
    info.processName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.state = static_cast<AppState>(fdp.ConsumeIntegralInRange<int32_t>(0, CODE_TWO));
    info.pid = fdp.ConsumeIntegral<uint32_t>();
    info.appIndex = fdp.ConsumeIntegral<int32_t>();
    info.instanceKey = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}

void GetRandomAppqfInfo(FuzzedDataProvider& fdp, AppqfInfo& deployedAppqfInfo)
{
    deployedAppqfInfo.type = static_cast<QuickFixType>(fdp.ConsumeIntegralInRange<int8_t>(0, CODE_TWO));
    deployedAppqfInfo.versionCode = fdp.ConsumeIntegral<int32_t>();
    deployedAppqfInfo.versionName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    deployedAppqfInfo.cpuAbi = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    deployedAppqfInfo.nativeLibraryPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::vector<HqfInfo> hqfInfos;
}

void GetRandomDeployingAppqfInfo(FuzzedDataProvider& fdp, AppqfInfo& deployingAppqfInfo)
{
    deployingAppqfInfo.type = static_cast<QuickFixType>(fdp.ConsumeIntegralInRange<int8_t>(0, CODE_TWO));
    deployingAppqfInfo.versionCode = fdp.ConsumeIntegral<int32_t>();
    deployingAppqfInfo.versionName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    deployingAppqfInfo.cpuAbi = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    deployingAppqfInfo.nativeLibraryPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::vector<HqfInfo> hqfInfos;
}

void GetRandomAppQuickFix(FuzzedDataProvider& fdp, AppQuickFix& appQuickFix)
{
    appQuickFix.versionCode = fdp.ConsumeIntegral<int32_t>();
    appQuickFix.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appQuickFix.versionName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    GetRandomAppqfInfo(fdp, appQuickFix.deployedAppqfInfo);
    GetRandomDeployingAppqfInfo(fdp, appQuickFix.deployingAppqfInfo);
}

void GetRandomResourceInfo(FuzzedDataProvider& fdp, Resource& labelResource)
{
    labelResource.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    labelResource.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    labelResource.id = fdp.ConsumeIntegral<int32_t>();
}

void GetRandomApplicationInfo(FuzzedDataProvider& fdp, ApplicationInfo& appInfo)
{
    appInfo.name = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.versionCode = fdp.ConsumeIntegral<int32_t>();
    appInfo.versionName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.minCompatibleVersionCode = fdp.ConsumeIntegral<int32_t>();
    appInfo.apiCompatibleVersion = fdp.ConsumeIntegral<int32_t>();
    appInfo.apiTargetVersion = fdp.ConsumeIntegral<int32_t>();
    appInfo.crowdtestDeadline = fdp.ConsumeIntegral<int64_t>();
    appInfo.iconPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.iconId = fdp.ConsumeIntegral<int32_t>();
    GetRandomResourceInfo(fdp, appInfo.labelResource);
    appInfo.label = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.labelId = fdp.ConsumeIntegral<int32_t>();
    GetRandomResourceInfo(fdp, appInfo.labelResource);
    appInfo.description = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.descriptionId = fdp.ConsumeIntegral<int32_t>();
    GetRandomResourceInfo(fdp, appInfo.labelResource);
    appInfo.keepAlive = fdp.ConsumeBool();
    appInfo.removable = fdp.ConsumeBool();
    appInfo.singleton = fdp.ConsumeBool();
    appInfo.userDataClearable = fdp.ConsumeBool();
    appInfo.allowAppRunWhenDeviceFirstLocked = fdp.ConsumeBool();
    appInfo.accessible = fdp.ConsumeBool();
    appInfo.runningResourcesApply = fdp.ConsumeBool();
    appInfo.associatedWakeUp = fdp.ConsumeBool();
    appInfo.hideDesktopIcon = fdp.ConsumeBool();
    appInfo.formVisibleNotify = fdp.ConsumeBool();
    appInfo.installedForAllUser = fdp.ConsumeBool();
    appInfo.allowEnableNotification = fdp.ConsumeBool();
    appInfo.allowMultiProcess = fdp.ConsumeBool();
    appInfo.gwpAsanEnabled = fdp.ConsumeBool();
    appInfo.hasPlugin = fdp.ConsumeBool();
    appInfo.allowCommonEvent = GenerateStringArray(fdp);
    appInfo.assetAccessGroups = GenerateStringArray(fdp);
    appInfo.isSystemApp = fdp.ConsumeBool();
    appInfo.isLauncherApp = fdp.ConsumeBool();
    appInfo.isFreeInstallApp = fdp.ConsumeBool();
    appInfo.asanEnabled = fdp.ConsumeBool();
    appInfo.asanLogPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.codePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.dataDir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.dataBaseDir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.cacheDir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.entryDir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.apiReleaseType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.debug = fdp.ConsumeBool();
    appInfo.deviceId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.distributedNotificationEnabled = fdp.ConsumeBool();
    appInfo.entityType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.process = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.supportedModes = fdp.ConsumeIntegral<int32_t>();
    appInfo.vendor = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.appPrivilegeLevel = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.appDistributionType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.appProvisionType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.accessTokenId = fdp.ConsumeIntegral<int32_t>();
    appInfo.applicationReservedFlag = fdp.ConsumeIntegral<int32_t>();
    appInfo.accessTokenIdEx = fdp.ConsumeIntegral<int64_t>();
    appInfo.enabled = fdp.ConsumeBool();
    appInfo.appIndex = fdp.ConsumeIntegral<int64_t>();
    appInfo.uid = fdp.ConsumeIntegral<int32_t>();
    appInfo.maxChildProcess = fdp.ConsumeIntegral<int32_t>();
    appInfo.nativeLibraryPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.cpuAbi = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.arkNativeFilePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.arkNativeFileAbi = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.permissions = GenerateStringArray(fdp);
    appInfo.moduleSourceDirs = GenerateStringArray(fdp);
    appInfo.targetBundleList = GenerateStringArray(fdp);
    appInfo.fingerprint = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    GetRandomAppQuickFix(fdp, appInfo.appQuickFix);
    appInfo.icon = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.flags = fdp.ConsumeIntegral<int32_t>();
    appInfo.entryModuleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.isCompressNativeLibs = fdp.ConsumeBool();
    appInfo.signatureKey = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.multiProjects = fdp.ConsumeBool();
    appInfo.tsanEnabled = fdp.ConsumeBool();
    appInfo.hwasanEnabled = fdp.ConsumeBool();
    appInfo.ubsanEnabled = fdp.ConsumeBool();
    appInfo.cloudFileSyncEnabled = fdp.ConsumeBool();
    appInfo.needAppDetail = fdp.ConsumeBool();
    appInfo.appDetailAbilityLibraryPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.targetBundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.targetPriority = fdp.ConsumeIntegral<int32_t>();
    appInfo.overlayState = fdp.ConsumeIntegral<int32_t>();
    appInfo.bundleType = static_cast<BundleType>(fdp.ConsumeIntegralInRange<int32_t>(0, CODE_TWO));
    appInfo.compileSdkVersion = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.compileSdkType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.organization = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.installSource = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appInfo.configuration = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}

void GetRandomAbilityRequestInfo(FuzzedDataProvider& fdp, AbilityRequest& info)
{
    info.restart = fdp.ConsumeBool();
    info.startRecent = fdp.ConsumeBool();
    info.uriReservedFlag = fdp.ConsumeBool();
    info.isFromIcon = fdp.ConsumeBool();
    info.isShellCall = fdp.ConsumeBool();
    info.isQueryERMS = fdp.ConsumeBool();
    info.isEmbeddedAllowed = fdp.ConsumeBool();
    info.callSpecifiedFlagTimeout = fdp.ConsumeBool();
    info.hideStartWindow = fdp.ConsumeBool();
    info.restartCount = fdp.ConsumeIntegral<uint32_t>();
    info.uid = fdp.ConsumeIntegral<uint32_t>();
    info.collaboratorType = static_cast<CollaboratorType>(fdp.ConsumeIntegralInRange<int32_t>(0, CODE_TWO));
    info.callerTokenRecordId = fdp.ConsumeIntegral<uint32_t>();
    info.userId = fdp.ConsumeIntegral<uint32_t>();
    info.callerAccessTokenId = fdp.ConsumeIntegral<uint32_t>();
    info.specifyTokenId = fdp.ConsumeIntegral<uint32_t>();
    info.callerUid = fdp.ConsumeIntegral<uint32_t>();
    info.requestCode = fdp.ConsumeIntegral<uint32_t>();
    info.callType = static_cast<AbilityCallType>(fdp.ConsumeIntegralInRange<int32_t>(0, CODE_TWO));
    info.restartTime = fdp.ConsumeIntegral<uint64_t>();
    info.extensionType = static_cast<ExtensionAbilityType>(fdp.ConsumeIntegralInRange<int32_t>(0, CODE_TWO));
    info.extensionProcessMode = static_cast<ExtensionProcessMode>(fdp.ConsumeIntegralInRange<int32_t>(0, CODE_TWO));
    info.specifiedFlag = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.customProcess = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.reservedBundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.appId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.startTime = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    Want want;
    GetRandomAbilityInfo(fdp, info.abilityInfo);
    GetRandomApplicationInfo(fdp, info.appInfo);
}

void GetRandomStartOptions(FuzzedDataProvider& fdp, StartOptions& startOptions)
{
    startOptions.windowLeftUsed_ = fdp.ConsumeBool();
    startOptions.windowTopUsed_ = fdp.ConsumeBool();
    startOptions.windowWidthUsed_ = fdp.ConsumeBool();
    startOptions.windowHeightUsed_ = fdp.ConsumeBool();
    startOptions.minWindowWidthUsed_ = fdp.ConsumeBool();
    startOptions.minWindowHeightUsed_ = fdp.ConsumeBool();
    startOptions.maxWindowWidthUsed_ = fdp.ConsumeBool();
    startOptions.maxWindowHeightUsed_ = fdp.ConsumeBool();
    startOptions.requestId_ = fdp.ConsumeRandomLengthString();
    startOptions.SetWithAnimation(fdp.ConsumeBool());
    startOptions.SetWindowFocused(fdp.ConsumeBool());
    startOptions.SetHideStartWindow(fdp.ConsumeBool());
    startOptions.SetWindowMode(fdp.ConsumeIntegral<int32_t>());
    startOptions.SetDisplayID(fdp.ConsumeIntegral<int32_t>());
    startOptions.SetWindowLeft(fdp.ConsumeIntegral<int32_t>());
    startOptions.SetWindowTop(fdp.ConsumeIntegral<int32_t>());
    startOptions.SetWindowWidth(fdp.ConsumeIntegral<int32_t>());
    startOptions.SetWindowHeight(fdp.ConsumeIntegral<int32_t>());
    startOptions.SetMinWindowWidth(fdp.ConsumeIntegral<int32_t>());
    startOptions.SetMinWindowHeight(fdp.ConsumeIntegral<int32_t>());
    startOptions.SetMaxWindowWidth(fdp.ConsumeIntegral<int32_t>());
    startOptions.SetMaxWindowHeight(fdp.ConsumeIntegral<int32_t>());
}

void GenerateBundleInfo(FuzzedDataProvider& fdp, AppExecFwk::BundleInfo &bundleInfo)
{
    bundleInfo.isNewVersion = fdp.ConsumeBool();
    bundleInfo.isKeepAlive = fdp.ConsumeBool();
    bundleInfo.singleton = fdp.ConsumeBool();
    bundleInfo.isPreInstallApp = fdp.ConsumeBool();
    bundleInfo.isNativeApp = fdp.ConsumeBool();
    bundleInfo.entryInstallationFree = fdp.ConsumeBool();
    bundleInfo.isDifferentName = fdp.ConsumeBool();
    bundleInfo.versionCode = fdp.ConsumeIntegral<uint32_t>();
    bundleInfo.minCompatibleVersionCode = fdp.ConsumeIntegral<uint32_t>();
    bundleInfo.compatibleVersion = fdp.ConsumeIntegral<uint32_t>();
    bundleInfo.targetVersion = fdp.ConsumeIntegral<uint32_t>();
    bundleInfo.appIndex = fdp.ConsumeIntegral<int32_t>();
    bundleInfo.minSdkVersion = fdp.ConsumeIntegral<int32_t>();
    bundleInfo.maxSdkVersion = fdp.ConsumeIntegral<int32_t>();
    bundleInfo.overlayType = fdp.ConsumeIntegralInRange<int32_t>(CODE_MIN_ONE, CODE_MAX_THREE);
    bundleInfo.uid = fdp.ConsumeIntegral<int>();
    bundleInfo.gid = fdp.ConsumeIntegral<int>();
    bundleInfo.installTime = fdp.ConsumeIntegral<int64_t>();
    bundleInfo.updateTime = fdp.ConsumeIntegral<int64_t>();
    bundleInfo.firstInstallTime = fdp.ConsumeIntegral<int64_t>();
    bundleInfo.name = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleInfo.versionName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleInfo.vendor = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleInfo.releaseType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleInfo.mainEntry = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleInfo.entryModuleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleInfo.appId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleInfo.cpuAbi = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleInfo.seInfo = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleInfo.label = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleInfo.description = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleInfo.jointUserId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);

    GenerateSignatureInfo(fdp, bundleInfo.signatureInfo);

    bundleInfo.oldAppIds = GenerateStringArray(fdp);
    bundleInfo.hapModuleNames = GenerateStringArray(fdp);
    bundleInfo.moduleNames = GenerateStringArray(fdp);
    bundleInfo.modulePublicDirs = GenerateStringArray(fdp);
    bundleInfo.moduleDirs = GenerateStringArray(fdp);
    bundleInfo.moduleResPaths = GenerateStringArray(fdp);

    bundleInfo.reqPermissions = GenerateStringArray(fdp);
    bundleInfo.defPermissions = GenerateStringArray(fdp);
}

std::vector<AppExecFwk::BundleInfo> GenerateBundleInfoArray(FuzzedDataProvider& fdp, size_t arraySizeMax = CODE_TEN)
{
    std::vector<AppExecFwk::BundleInfo> result;
    size_t arraySize = fdp.ConsumeIntegralInRange<size_t>(0, arraySizeMax);
    result.reserve(arraySize);

    for (size_t i = 0; i < arraySize; ++i) {
        AppExecFwk::BundleInfo bundleInfo;
        GenerateBundleInfo(fdp, bundleInfo);
        result.emplace_back(bundleInfo);
    }

    return result;
}

Resource GenerateResource(FuzzedDataProvider& fdp)
{
    Resource info;
    info.id = fdp.ConsumeIntegral<uint32_t>();
    info.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    return info;
}

void GenerateApplicationInfo(FuzzedDataProvider& fdp, AppExecFwk::ApplicationInfo &applicationInfo)
{
    applicationInfo.keepAlive = fdp.ConsumeBool();
    applicationInfo.removable = fdp.ConsumeBool();
    applicationInfo.singleton = fdp.ConsumeBool();
    applicationInfo.userDataClearable = fdp.ConsumeBool();
    applicationInfo.allowAppRunWhenDeviceFirstLocked = fdp.ConsumeBool();
    applicationInfo.accessible = fdp.ConsumeBool();
    applicationInfo.runningResourcesApply = fdp.ConsumeBool();
    applicationInfo.associatedWakeUp = fdp.ConsumeBool();
    applicationInfo.hideDesktopIcon = fdp.ConsumeBool();
    applicationInfo.formVisibleNotify = fdp.ConsumeBool();
    applicationInfo.isSystemApp = fdp.ConsumeBool();
    applicationInfo.isLauncherApp = fdp.ConsumeBool();
    applicationInfo.isFreeInstallApp = fdp.ConsumeBool();
    applicationInfo.asanEnabled = fdp.ConsumeBool();
    applicationInfo.debug = fdp.ConsumeBool();
    applicationInfo.distributedNotificationEnabled = fdp.ConsumeBool();
    applicationInfo.installedForAllUser = fdp.ConsumeBool();
    applicationInfo.allowEnableNotification = fdp.ConsumeBool();
    applicationInfo.allowMultiProcess = fdp.ConsumeBool();
    applicationInfo.gwpAsanEnabled = fdp.ConsumeBool();
    applicationInfo.enabled = fdp.ConsumeBool();
    applicationInfo.hasPlugin = fdp.ConsumeBool();
    applicationInfo.multiProjects = fdp.ConsumeBool();
    applicationInfo.isCompressNativeLibs = fdp.ConsumeBool();
    applicationInfo.tsanEnabled = fdp.ConsumeBool();
    applicationInfo.hwasanEnabled = fdp.ConsumeBool();
    applicationInfo.ubsanEnabled = fdp.ConsumeBool();
    applicationInfo.cloudFileSyncEnabled = fdp.ConsumeBool();
    applicationInfo.cloudStructuredDataSyncEnabled = fdp.ConsumeBool();
    applicationInfo.needAppDetail = fdp.ConsumeBool();
    applicationInfo.versionCode = fdp.ConsumeIntegral<uint32_t>();
    applicationInfo.apiCompatibleVersion = fdp.ConsumeIntegral<uint32_t>();
    applicationInfo.iconId = fdp.ConsumeIntegral<uint32_t>();
    applicationInfo.labelId = fdp.ConsumeIntegral<uint32_t>();
    applicationInfo.descriptionId = fdp.ConsumeIntegral<uint32_t>();
    applicationInfo.accessTokenId = fdp.ConsumeIntegral<uint32_t>();
    applicationInfo.applicationReservedFlag = fdp.ConsumeIntegral<uint32_t>();
    applicationInfo.apiTargetVersion = fdp.ConsumeIntegral<int32_t>();
    applicationInfo.minCompatibleVersionCode = fdp.ConsumeIntegral<int32_t>();
    applicationInfo.supportedModes = fdp.ConsumeIntegral<int32_t>();
    applicationInfo.appIndex = fdp.ConsumeIntegral<int32_t>();
    applicationInfo.uid = fdp.ConsumeIntegral<int32_t>();
    applicationInfo.flags = fdp.ConsumeIntegral<int32_t>();
    applicationInfo.targetPriority = fdp.ConsumeIntegral<int32_t>();
    applicationInfo.overlayState = fdp.ConsumeIntegral<int32_t>();
    applicationInfo.maxChildProcess = fdp.ConsumeIntegral<int32_t>();
    applicationInfo.applicationFlags = fdp.ConsumeIntegral<int32_t>();
    applicationInfo.bundleType = static_cast<BundleType>(fdp.ConsumeIntegralInRange<int32_t>(0, CODE_FOUR));
    applicationInfo.crowdtestDeadline = fdp.ConsumeIntegral<int64_t>();
    applicationInfo.accessTokenIdEx = fdp.ConsumeIntegral<uint64_t>();
    applicationInfo.name = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.versionName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.iconPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.label = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.description = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.asanLogPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.codePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.dataDir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.dataBaseDir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.cacheDir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.entryDir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.apiReleaseType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.deviceId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.entityType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.process = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.vendor = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.appPrivilegeLevel = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.appDistributionType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.appProvisionType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.nativeLibraryPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.cpuAbi = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.arkNativeFilePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.arkNativeFileAbi = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.fingerprint = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.icon = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.entryModuleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.signatureKey = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.targetBundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.compileSdkVersion = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.compileSdkType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.organization = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.appDetailAbilityLibraryPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.installSource = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.configuration = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    applicationInfo.iconResource = GenerateResource(fdp);
    applicationInfo.labelResource = GenerateResource(fdp);
    applicationInfo.descriptionResource = GenerateResource(fdp);

    applicationInfo.allowCommonEvent = GenerateStringArray(fdp);
    applicationInfo.assetAccessGroups = GenerateStringArray(fdp);

    applicationInfo.permissions = GenerateStringArray(fdp);
    applicationInfo.moduleSourceDirs = GenerateStringArray(fdp);
    applicationInfo.targetBundleList = GenerateStringArray(fdp);
}
}  // namespace AbilityFuzzUtil
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // BMS_FUZZTEST_UTIL_H