/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "application_context.h"

#include "ability_business_error_utils.h"
#include "ability_manager_client.h"
#include "context.h"
#include "context/application_context.h"
#include "hilog_tag_wrapper.h"
#include "start_options_impl.h"
#include "want_manager.h"
#include "want_utils.h"

using namespace OHOS::AbilityRuntime;
using namespace OHOS::AAFwk;
using namespace OHOS;

namespace {
AbilityRuntime_ErrorCode WriteStringToBuffer(
    const std::string &src, char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    const auto srcLength = static_cast<int32_t>(src.length());
    if (bufferSize - 1 < srcLength) {
        TAG_LOGE(AAFwkTag::APPKIT, "the buffer size is less than the minimum buffer size");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    src.copy(buffer, srcLength);
    buffer[srcLength] = '\0';
    *writeLength = srcLength;
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode CheckParameters(char* buffer, int32_t* writeLength)
{
    if (buffer == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "buffer is null");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    if (writeLength == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "writeLength is null");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_ApplicationContextGetCacheDir(
    char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    if (buffer == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "buffer is null");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    if (writeLength == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "writeLength is null");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }

    const auto appContext = Context::GetApplicationContext();
    if (appContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "appContext is null");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    const std::string cacheDir = appContext->GetCacheDir();
    if (cacheDir.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "cacheDir is empty");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    return WriteStringToBuffer(cacheDir, buffer, bufferSize, writeLength);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_ApplicationContextGetAreaMode(AbilityRuntime_AreaMode* areaMode)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    if (areaMode == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "areaMode is null");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }

    const auto appContext = Context::GetApplicationContext();
    if (appContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "appContext is null");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    int32_t area = appContext->GetArea();
    *areaMode = static_cast<AbilityRuntime_AreaMode>(area);
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_ApplicationContextGetBundleName(
    char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    if (buffer == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "buffer is null");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    if (writeLength == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "writeLength is null");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }

    const auto appContext = Context::GetApplicationContext();
    if (appContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "appContext is null");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    const std::string bundleName = appContext->GetBundleName();
    if (bundleName.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "bundleName is empty");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    return WriteStringToBuffer(bundleName, buffer, bufferSize, writeLength);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_ApplicationContextGetTempDir(
    char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    TAG_LOGD(AAFwkTag::APPKIT, "getTempDir called");
    auto ret = CheckParameters(buffer, writeLength);
    if (ret != ABILITY_RUNTIME_ERROR_CODE_NO_ERROR) {
        return ret;
    }
    const auto appContext = Context::GetApplicationContext();
    if (appContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "appContext is null");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    const std::string tempDir = appContext->GetTempDir();
    if (tempDir.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "tempDir is empty");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    return WriteStringToBuffer(tempDir, buffer, bufferSize, writeLength);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_ApplicationContextGetFilesDir(
    char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    TAG_LOGD(AAFwkTag::APPKIT, "getFilesDir called");
    auto ret = CheckParameters(buffer, writeLength);
    if (ret != ABILITY_RUNTIME_ERROR_CODE_NO_ERROR) {
        return ret;
    }
    const auto appContext = Context::GetApplicationContext();
    if (appContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "appContext is null");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    const std::string filesDir = appContext->GetFilesDir();
    if (filesDir.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "filesDir is empty");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    return WriteStringToBuffer(filesDir, buffer, bufferSize, writeLength);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_ApplicationContextGetDatabaseDir(
    char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    TAG_LOGD(AAFwkTag::APPKIT, "getDatabaseDir called");
    auto ret = CheckParameters(buffer, writeLength);
    if (ret != ABILITY_RUNTIME_ERROR_CODE_NO_ERROR) {
        return ret;
    }
    const auto appContext = Context::GetApplicationContext();
    if (appContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "appContext is null");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    const std::string databaseDir = appContext->GetDatabaseDir();
    if (databaseDir.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "databaseDir is empty");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    return WriteStringToBuffer(databaseDir, buffer, bufferSize, writeLength);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_ApplicationContextGetPreferencesDir(
    char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    TAG_LOGD(AAFwkTag::APPKIT, "getPreferencesDir called");
    auto ret = CheckParameters(buffer, writeLength);
    if (ret != ABILITY_RUNTIME_ERROR_CODE_NO_ERROR) {
        return ret;
    }
    const auto appContext = Context::GetApplicationContext();
    if (appContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "appContext is null");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    const std::string preferencesDir = appContext->GetPreferencesDir();
    if (preferencesDir.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "preferencesDir is empty");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    return WriteStringToBuffer(preferencesDir, buffer, bufferSize, writeLength);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_ApplicationContextGetBundleCodeDir(
    char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    TAG_LOGD(AAFwkTag::APPKIT, "getBundleCodeDir called");
    auto ret = CheckParameters(buffer, writeLength);
    if (ret != ABILITY_RUNTIME_ERROR_CODE_NO_ERROR) {
        return ret;
    }
    const auto appContext = Context::GetApplicationContext();
    if (appContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "appContext is null");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    const std::string bundleCodeDir = appContext->GetBundleCodeDir();
    if (bundleCodeDir.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "bundleCodeDir is empty");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    return WriteStringToBuffer(bundleCodeDir, buffer, bufferSize, writeLength);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_ApplicationContextGetDistributedFilesDir(
    char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    TAG_LOGD(AAFwkTag::APPKIT, "getDistributedFilesDir called");
    auto ret = CheckParameters(buffer, writeLength);
    if (ret != ABILITY_RUNTIME_ERROR_CODE_NO_ERROR) {
        return ret;
    }
    const auto appContext = Context::GetApplicationContext();
    if (appContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "appContext is null");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    const std::string distributedFilesDir = appContext->GetDistributedFilesDir();
    if (distributedFilesDir.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "distributedFilesDir is empty");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    return WriteStringToBuffer(distributedFilesDir, buffer, bufferSize, writeLength);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_ApplicationContextGetCloudFileDir(
    char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    TAG_LOGD(AAFwkTag::APPKIT, "getCloudFileDir called");
    auto ret = CheckParameters(buffer, writeLength);
    if (ret != ABILITY_RUNTIME_ERROR_CODE_NO_ERROR) {
        return ret;
    }
    const auto appContext = Context::GetApplicationContext();
    if (appContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "appContext is null");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    const std::string cloudFileDir = appContext->GetCloudFileDir();
    if (cloudFileDir.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "cloudFileDir is empty");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    return WriteStringToBuffer(cloudFileDir, buffer, bufferSize, writeLength);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_ApplicationContextGetResourceDir(const char* moduleName,
    char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    TAG_LOGD(AAFwkTag::APPKIT, "getResourceDir called");
    if (moduleName == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "moduleName is null");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    if (std::strlen(moduleName) == 0) {
        TAG_LOGE(AAFwkTag::APPKIT, "moduleName is empty");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    auto ret = CheckParameters(buffer, writeLength);
    if (ret != ABILITY_RUNTIME_ERROR_CODE_NO_ERROR) {
        return ret;
    }
    const auto appContext = Context::GetApplicationContext();
    if (appContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "appContext is null");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    const std::string resourceDir = appContext->GetResourceDir(moduleName);
    if (resourceDir.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "resourceDir is empty");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    return WriteStringToBuffer(resourceDir, buffer, bufferSize, writeLength);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_StartSelfUIAbility(AbilityBase_Want *want)
{
    TAG_LOGD(AAFwkTag::APPKIT, "startSelfUIAbility called");
    auto ret = CheckWant(want);
    if (ret != ABILITY_RUNTIME_ERROR_CODE_NO_ERROR) {
        TAG_LOGE(AAFwkTag::APPKIT, "CheckWant failed: %{public}d", ret);
        return ret;
    }
    Want abilityWant;
    AbilityBase_ErrorCode errCode = CWantManager::TransformToWant(*want, false, abilityWant);
    if (errCode != ABILITY_BASE_ERROR_CODE_NO_ERROR) {
        TAG_LOGE(AAFwkTag::APPKIT, "transform error:%{public}d", errCode);
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return ConvertToCommonBusinessErrorCode(AbilityManagerClient::GetInstance()->StartSelfUIAbility(abilityWant));
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_StartSelfUIAbilityWithStartOptions(AbilityBase_Want *want,
    AbilityRuntime_StartOptions *options)
{
    TAG_LOGD(AAFwkTag::APPKIT, "startSelfUIAbility called");
    auto ret = CheckWant(want);
    if (ret != ABILITY_RUNTIME_ERROR_CODE_NO_ERROR) {
        TAG_LOGE(AAFwkTag::APPKIT, "CheckWant failed: %{public}d", ret);
        return ret;
    }
    if (options == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null options");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    Want abilityWant;
    AbilityBase_ErrorCode errCode = CWantManager::TransformToWant(*want, false, abilityWant);
    if (errCode != ABILITY_BASE_ERROR_CODE_NO_ERROR) {
        TAG_LOGE(AAFwkTag::APPKIT, "transform error:%{public}d", errCode);
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    OHOS::AAFwk::StartOptions startOptions = options->GetInnerStartOptions();
    return ConvertToAPI18BusinessErrorCode(AbilityManagerClient::GetInstance()->StartSelfUIAbilityWithStartOptions(
        abilityWant, startOptions));
}