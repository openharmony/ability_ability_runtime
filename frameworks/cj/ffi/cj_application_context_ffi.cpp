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

#include "cj_application_context_ffi.h"

#include "ability_delegator_registry.h"
#include "ability_manager_errors.h"
#include "application_context.h"
#include "cj_ability_runtime_error.h"
#include "cj_application_context.h"
#include "cj_lambda.h"
#include "cj_utils_ffi.h"
#include "hilog_tag_wrapper.h"
#include "running_process_info.h"

namespace OHOS {
namespace ApplicationContextCJ {
using namespace OHOS::FFI;
using namespace OHOS::AbilityRuntime;

extern "C" {
int64_t FFIGetArea(int64_t id)
{
    auto context = FFI::FFIData::GetData<CJApplicationContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return INVALID_CODE;
    }
    return context->GetArea();
}

CApplicationInfo *FFICJApplicationInfo(int64_t id)
{
    auto context = FFI::FFIData::GetData<CJApplicationContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    auto appInfo = context->GetApplicationInfo();
    CApplicationInfo *buffer = static_cast<CApplicationInfo *>(malloc(sizeof(CApplicationInfo)));
    if (buffer == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "malloc appinfo fail");
        return nullptr;
    }
    buffer->name = CreateCStringFromString(appInfo->name);
    buffer->bundleName = CreateCStringFromString(appInfo->bundleName);
    return buffer;
}

int32_t FfiCJApplicationContextOnOnEnvironment(int64_t id, void (*cfgCallback)(CConfiguration),
                                               void (*memCallback)(int32_t), int32_t *errCode)
{
    auto context = FFI::FFIData::GetData<CJApplicationContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return -1;
    }
    return context->OnOnEnvironment(cfgCallback, memCallback, false, errCode);
}

int32_t FfiCJApplicationContextOnOnAbilityLifecycle(int64_t id, CArrI64 cFuncIds, int32_t *errCode)
{
    auto context = FFI::FFIData::GetData<CJApplicationContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return -1;
    }
    return context->OnOnAbilityLifecycle(cFuncIds, false, errCode);
}

int32_t FfiCJApplicationContextOnOnApplicationStateChange(int64_t id, void (*foregroundCallback)(void),
                                                          void (*backgroundCallback)(void), int32_t *errCode)
{
    auto context = FFI::FFIData::GetData<CJApplicationContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return -1;
    }
    return context->OnOnApplicationStateChange(foregroundCallback, backgroundCallback, errCode);
}

void FfiCJApplicationContextOnOff(int64_t id, const char *type, int32_t callbackId, int32_t *errCode)
{
    auto context = FFI::FFIData::GetData<CJApplicationContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return;
    }
    auto typeString = std::string(type);
    if (typeString == "environment") {
        return context->OnOffEnvironment(callbackId, errCode);
    }
    if (typeString == "abilityLifecycle") {
        return context->OnOffAbilityLifecycle(callbackId, errCode);
    }
    if (typeString == "applicationStateChange") {
        return context->OnOffApplicationStateChange(callbackId, errCode);
    }
    TAG_LOGE(AAFwkTag::CONTEXT, "off function type not match");
    *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
    return;
}

void FfiCJApplicationContextSetFont(int64_t id, const char *font, int32_t *errCode)
{
    auto context = FFI::FFIData::GetData<CJApplicationContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return;
    }
    auto fontString = std::string(font);
    context->OnSetFont(fontString);
}

void FfiCJApplicationContextSetLanguage(int64_t id, const char *language, int32_t *errCode)
{
    auto context = FFI::FFIData::GetData<CJApplicationContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return;
    }
    auto languageString = std::string(language);
    context->OnSetLanguage(languageString);
}

void FfiCJApplicationContextSetColorMode(int64_t id, int32_t colorMode, int32_t *errCode)
{
    auto context = FFI::FFIData::GetData<CJApplicationContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return;
    }
    context->OnSetColorMode(colorMode);
}

CjAppProcessState ConvertToJsAppProcessState(const AppExecFwk::AppProcessState &appProcessState, const bool &isFocused)
{
    CjAppProcessState processState;
    switch (appProcessState) {
        case AppExecFwk::AppProcessState::APP_STATE_CREATE:
        case AppExecFwk::AppProcessState::APP_STATE_READY:
            processState = STATE_CREATE;
            break;
        case AppExecFwk::AppProcessState::APP_STATE_FOREGROUND:
            processState = isFocused ? STATE_ACTIVE : STATE_FOREGROUND;
            break;
        case AppExecFwk::AppProcessState::APP_STATE_BACKGROUND:
            processState = STATE_BACKGROUND;
            break;
        case AppExecFwk::AppProcessState::APP_STATE_TERMINATED:
        case AppExecFwk::AppProcessState::APP_STATE_END:
            processState = STATE_DESTROY;
            break;
        default:
            TAG_LOGE(AAFwkTag::CONTEXT, "Process state is invalid.");
            processState = STATE_DESTROY;
            break;
    }
    return processState;
}

CArrProcessInformation FfiCJApplicationContextGetRunningProcessInformation(int64_t id, int32_t *errCode)
{
    CArrProcessInformation cArrProcessInformation = {.head = nullptr, .size = 0};
    auto context = FFI::FFIData::GetData<CJApplicationContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return cArrProcessInformation;
    }
    auto processInfo = context->OnGetRunningProcessInformation(errCode);
    if (*errCode != ERR_OK) {
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INTERNAL_ERROR;
        return cArrProcessInformation;
    }

    CProcessInformation *head = static_cast<CProcessInformation *>(malloc(sizeof(CProcessInformation)));
    if (head == nullptr) {
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INTERNAL_ERROR;
        return cArrProcessInformation;
    }
    head->processName = CreateCStringFromString(processInfo->processName_);
    head->pid = processInfo->pid_;
    head->uid = processInfo->uid_;
    head->bundleNames.head = VectorToCArrString(processInfo->bundleNames);
    head->bundleNames.size = (processInfo->bundleNames).size();
    head->state = ConvertToJsAppProcessState(processInfo->state_, processInfo->isFocused);
    head->bundleType = processInfo->bundleType;
    head->appCloneIndex = processInfo->appCloneIndex;
    cArrProcessInformation.size = 1;
    cArrProcessInformation.head = head;
    return cArrProcessInformation;
}

void FfiCJApplicationContextKillAllProcesses(int64_t id, bool clearPageStack, int32_t *errCode)
{
    auto context = FFI::FFIData::GetData<CJApplicationContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return;
    }
    context->OnKillProcessBySelf(clearPageStack, errCode);
}

int32_t FfiCJApplicationContextGetCurrentAppCloneIndex(int64_t id, int32_t *errCode)
{
    auto context = FFI::FFIData::GetData<CJApplicationContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return -1;
    }
    return context->OnGetCurrentAppCloneIndex(errCode);
}

void FfiCJApplicationContextRestartApp(int64_t id, WantHandle want, int32_t *errCode)
{
    auto context = FFI::FFIData::GetData<CJApplicationContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return;
    }
    auto actualWant = reinterpret_cast<AAFwk::Want *>(want);
    if (actualWant == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null want");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return;
    }
    return context->OnRestartApp(*actualWant, errCode);
}

void FfiCJApplicationContextClearUpApplicationData(int64_t id, int32_t *errCode)
{
    auto context = FFI::FFIData::GetData<CJApplicationContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return;
    }
    return context->OnClearUpApplicationData(errCode);
}

void FfiCJApplicationContextSetSupportedProcessCache(int64_t id, bool isSupported, int32_t *errCode)
{
    auto context = FFI::FFIData::GetData<CJApplicationContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return;
    }
    return context->OnSetSupportedProcessCacheSelf(isSupported, errCode);
}
}
} // namespace ApplicationContextCJ
} // namespace OHOS