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

#include "application_context.h"

#include "context.h"
#include "context/application_context.h"
#include "hilog_tag_wrapper.h"

using namespace OHOS::AbilityRuntime;

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
