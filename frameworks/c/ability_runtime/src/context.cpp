/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "ability_runtime/context.h"

#include "native_extension/context_impl.h"
#include "hilog_tag_wrapper.h"

using namespace OHOS::AbilityRuntime;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;
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

AbilityRuntime_ErrorCode CheckParameters(AbilityRuntime_ContextHandle context, char* buffer, int32_t* writeLength)
{
    if (buffer == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "buffer is null");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    if (writeLength == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "writeLength is null");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "context is null");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}
} // namespace

#ifdef __cplusplus
extern "C" {
#endif

AbilityRuntime_ErrorCode OH_AbilityRuntime_Context_GetCacheDir(
    AbilityRuntime_ContextHandle context, char* buffer, int32_t bufferSize, int32_t* writeLength)
{
    auto ret = CheckParameters(context, buffer, writeLength);
    if (ret != ABILITY_RUNTIME_ERROR_CODE_NO_ERROR) {
        return ret;
    }
    auto weakContext = context->context.lock();
    if (weakContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "weak context is null");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    const std::string cacheDir = weakContext->GetCacheDir();
    if (cacheDir.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "cacheDir is empty");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    return WriteStringToBuffer(cacheDir, buffer, bufferSize, writeLength);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_Context_GetTempDir(
    AbilityRuntime_ContextHandle context, char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    auto ret = CheckParameters(context, buffer, writeLength);
    if (ret != ABILITY_RUNTIME_ERROR_CODE_NO_ERROR) {
        return ret;
    }
    auto weakContext = context->context.lock();
    if (weakContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "weak context is null");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    const std::string tempDir = weakContext->GetTempDir();
    if (tempDir.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "tempDir is empty");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    return WriteStringToBuffer(tempDir, buffer, bufferSize, writeLength);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_Context_GetFilesDir(
    AbilityRuntime_ContextHandle context, char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    auto ret = CheckParameters(context, buffer, writeLength);
    if (ret != ABILITY_RUNTIME_ERROR_CODE_NO_ERROR) {
        return ret;
    }
    auto weakContext = context->context.lock();
    if (weakContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "weak context is null");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    const std::string filesDir = weakContext->GetFilesDir();
    if (filesDir.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "filesDir is empty");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    return WriteStringToBuffer(filesDir, buffer, bufferSize, writeLength);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_Context_GetDatabaseDir(
    AbilityRuntime_ContextHandle context, char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    auto ret = CheckParameters(context, buffer, writeLength);
    if (ret != ABILITY_RUNTIME_ERROR_CODE_NO_ERROR) {
        return ret;
    }
    auto weakContext = context->context.lock();
    if (weakContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "weak context is null");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    const std::string databaseDir = weakContext->GetDatabaseDir();
    if (databaseDir.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "databaseDir is empty");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    return WriteStringToBuffer(databaseDir, buffer, bufferSize, writeLength);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_Context_GetPreferencesDir(
    AbilityRuntime_ContextHandle context, char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    auto ret = CheckParameters(context, buffer, writeLength);
    if (ret != ABILITY_RUNTIME_ERROR_CODE_NO_ERROR) {
        return ret;
    }
    auto weakContext = context->context.lock();
    if (weakContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "weak context is null");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    const std::string preferencesDir = weakContext->GetPreferencesDir();
    if (preferencesDir.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "preferencesDir is empty");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    return WriteStringToBuffer(preferencesDir, buffer, bufferSize, writeLength);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_Context_GetBundleCodeDir(
    AbilityRuntime_ContextHandle context, char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    auto ret = CheckParameters(context, buffer, writeLength);
    if (ret != ABILITY_RUNTIME_ERROR_CODE_NO_ERROR) {
        return ret;
    }
    auto weakContext = context->context.lock();
    if (weakContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "weak context is null");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    const std::string bundleCodeDir = weakContext->GetBundleCodeDir();
    if (bundleCodeDir.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "bundleCodeDir is empty");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    return WriteStringToBuffer(bundleCodeDir, buffer, bufferSize, writeLength);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_Context_GetDistributedFilesDir(
    AbilityRuntime_ContextHandle context, char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    auto ret = CheckParameters(context, buffer, writeLength);
    if (ret != ABILITY_RUNTIME_ERROR_CODE_NO_ERROR) {
        return ret;
    }
    auto weakContext = context->context.lock();
    if (weakContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "weak context is null");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    const std::string distributedFilesDir = weakContext->GetDistributedFilesDir();
    if (distributedFilesDir.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "distributedFilesDir is empty");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    return WriteStringToBuffer(distributedFilesDir, buffer, bufferSize, writeLength);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_Context_GetResourceDir(AbilityRuntime_ContextHandle context,
    char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    auto ret = CheckParameters(context, buffer, writeLength);
    if (ret != ABILITY_RUNTIME_ERROR_CODE_NO_ERROR) {
        return ret;
    }
    auto weakContext = context->context.lock();
    if (weakContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "weak context is null");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    const std::string resourceDir = weakContext->GetResourceDir();
    if (resourceDir.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "resourceDir is empty");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    return WriteStringToBuffer(resourceDir, buffer, bufferSize, writeLength);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_Context_GetCloudFileDir(
    AbilityRuntime_ContextHandle context, char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    auto ret = CheckParameters(context, buffer, writeLength);
    if (ret != ABILITY_RUNTIME_ERROR_CODE_NO_ERROR) {
        return ret;
    }
    auto weakContext = context->context.lock();
    if (weakContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "weak context is null");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    const std::string cloudFileDir = weakContext->GetCloudFileDir();
    if (cloudFileDir.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "cloudFileDir is empty");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    return WriteStringToBuffer(cloudFileDir, buffer, bufferSize, writeLength);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_Context_GetAreaMode(
    AbilityRuntime_ContextHandle context, AbilityRuntime_AreaMode* areaMode)
{
    if (areaMode == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "areaMode is null");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "context is null");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    auto weakContext = context->context.lock();
    if (weakContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "weak context is null");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    int32_t area = weakContext->GetArea();
    *areaMode = static_cast<AbilityRuntime_AreaMode>(area);
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_Context_SetArea(
    AbilityRuntime_ContextHandle context, AbilityRuntime_AreaMode areaMode)
{
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "context is null");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    auto weakContext = context->context.lock();
    if (weakContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "weak context is null");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    weakContext->SwitchArea(static_cast<int>(areaMode));
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_Context_GetLogFileDir(
    AbilityRuntime_ContextHandle context, char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    auto ret = CheckParameters(context, buffer, writeLength);
    if (ret != ABILITY_RUNTIME_ERROR_CODE_NO_ERROR) {
        return ret;
    }
    auto weakContext = context->context.lock();
    if (weakContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "weak context is null");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    const std::string logFileDir = weakContext->GetLogFileDir();
    if (logFileDir.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "logFileDir is empty");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    return WriteStringToBuffer(logFileDir, buffer, bufferSize, writeLength);
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_Context_GetProcessName(
    AbilityRuntime_ContextHandle context, char* buffer, int32_t bufferSize, int32_t* writeLength)
{
    auto ret = CheckParameters(context, buffer, writeLength);
    if (ret != ABILITY_RUNTIME_ERROR_CODE_NO_ERROR) {
        return ret;
    }
    auto weakContext = context->context.lock();
    if (weakContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "weak context is null");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    const std::string processName = weakContext->GetProcessName();
    if (processName.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "processName is empty");
        return ABILITY_RUNTIME_ERROR_CODE_CONTEXT_NOT_EXIST;
    }
    return WriteStringToBuffer(processName, buffer, bufferSize, writeLength);
}

#ifdef __cplusplus
} // extern "C"
#endif