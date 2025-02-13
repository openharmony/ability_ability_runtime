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

#include "ability_manager_client.h"
#include "context.h"
#include "context/application_context.h"
#include "hilog_tag_wrapper.h"
#include "want_manager.h"

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

AbilityRuntime_ErrorCode ConvertErrorCode(int32_t abilityManagerErrorCode)
{
    TAG_LOGI(AAFwkTag::APPKIT, "ability errCode:%{public}d", abilityManagerErrorCode);
    switch (abilityManagerErrorCode) {
        case ERR_OK:
            return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
        case CHECK_PERMISSION_FAILED:
            return ABILITY_RUNTIME_ERROR_CODE_PERMISSION_DENIED;
        case ERR_PERMISSION_DENIED:
            return ABILITY_RUNTIME_ERROR_CODE_PERMISSION_DENIED;
        case ERR_CAPABILITY_NOT_SUPPORT:
            return ABILITY_RUNTIME_ERROR_CODE_NOT_SUPPORTED;
        case RESOLVE_ABILITY_ERR:
            return ABILITY_RUNTIME_ERROR_CODE_NO_SUCH_ABILITY;
        case TARGET_BUNDLE_NOT_EXIST:
            return ABILITY_RUNTIME_ERROR_CODE_NO_SUCH_ABILITY;
        case ERR_NOT_ALLOW_IMPLICIT_START:
            return ABILITY_RUNTIME_ERROR_CODE_NO_SUCH_ABILITY;
        case ERR_WRONG_INTERFACE_CALL:
            return ABILITY_RUNTIME_ERROR_CODE_INCORRECT_ABILITY_TYPE;
        case TARGET_ABILITY_NOT_SERVICE:
            return ABILITY_RUNTIME_ERROR_CODE_INCORRECT_ABILITY_TYPE;
        case RESOLVE_CALL_ABILITY_TYPE_ERR:
            return ABILITY_RUNTIME_ERROR_CODE_INCORRECT_ABILITY_TYPE;
        case ERR_CROWDTEST_EXPIRED:
            return ABILITY_RUNTIME_ERROR_CODE_CROWDTEST_EXPIRED;
        case ERR_WOULD_BLOCK:
            return ABILITY_RUNTIME_ERROR_CODE_WUKONG_MODE;
        case ERR_APP_CONTROLLED:
            return ABILITY_RUNTIME_ERROR_CODE_CONTROLLED;
        case ERR_EDM_APP_CONTROLLED:
            return ABILITY_RUNTIME_ERROR_CODE_EDM_CONTROLLED;
        case NOT_TOP_ABILITY:
            return ABILITY_RUNTIME_ERROR_CODE_NOT_TOP_ABILITY;
    }
    return ABILITY_RUNTIME_ERROR_CODE_INTERNAL;
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_StartSelfUIAbility(AbilityBase_Want *want)
{
    TAG_LOGD(AAFwkTag::APPKIT, "startSelfUIAbility called");
    if (want == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null want");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    AbilityBase_Element element = want->element;
    if (element.bundleName == nullptr || element.abilityName == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "empty bundleName or abilityName");
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    Want abilityWant;
    AbilityBase_ErrorCode ret = CWantManager::TransformToWant(*want, false, abilityWant);
    if (ret != ABILITY_BASE_ERROR_CODE_NO_ERROR) {
        TAG_LOGE(AAFwkTag::APPKIT, "transform error:%{public}d", ret);
        return ABILITY_RUNTIME_ERROR_CODE_PARAM_INVALID;
    }
    return ConvertErrorCode(AbilityManagerClient::GetInstance()->StartSelfUIAbility(abilityWant));
}