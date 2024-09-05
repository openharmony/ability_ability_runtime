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
 
#include "cj_application_context.h"

#include "ability_delegator_registry.h"
#include "application_context.h"
#include "cj_utils_ffi.h"
#include "cj_lambda.h"
#include "hilog_tag_wrapper.h"
#include "cj_ability_runtime_error.h"

namespace OHOS {
namespace ApplicationContextCJ {
using namespace OHOS::FFI;
using namespace OHOS::AbilityRuntime;

int CJApplicationContext::GetArea()
{
    auto context = applicationContext_.lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return INVALID_CODE;
    }
    return context->GetArea();
}

std::shared_ptr<AppExecFwk::ApplicationInfo> CJApplicationContext::GetApplicationInfo()
{
    auto context = applicationContext_.lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    return context->GetApplicationInfo();
}

int32_t CJApplicationContext::OnOnEnvironment(void (*cfgCallback)(CConfiguration),
    void (*memCallback)(int32_t), bool isSync, int32_t *errCode)
{
    auto context = applicationContext_.lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INTERNAL_ERROR;
        return -1;
    }
    if (envCallback_ != nullptr) {
        TAG_LOGD(AAFwkTag::APPKIT, "envCallback_ is not nullptr.");
        return envCallback_->Register(CJLambda::Create(cfgCallback), CJLambda::Create(memCallback), isSync);
    }
    envCallback_ = std::make_shared<CjEnvironmentCallback>();
    int32_t callbackId = envCallback_->Register(CJLambda::Create(cfgCallback), CJLambda::Create(memCallback), isSync);
    context->RegisterEnvironmentCallback(envCallback_);
    TAG_LOGD(AAFwkTag::APPKIT, "OnOnEnvironment is end");
    return callbackId;
}

void CJApplicationContext::OnOffEnvironment(int32_t callbackId, int32_t *errCode)
{
    auto context = applicationContext_.lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return;
    }
    std::weak_ptr<CjEnvironmentCallback> envCallbackWeak(envCallback_);
    auto env_callback = envCallbackWeak.lock();
    if (env_callback == nullptr) {
        TAG_LOGD(AAFwkTag::APPKIT, "env_callback is not nullptr.");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return;
    }
    TAG_LOGD(AAFwkTag::APPKIT, "OnOffEnvironment begin");
    if (!env_callback->UnRegister(callbackId, false)) {
        TAG_LOGE(AAFwkTag::APPKIT, "call UnRegister failed");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return;
    }
}

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

CApplicationInfo* FFICJApplicationInfo(int64_t id)
{
    auto context = FFI::FFIData::GetData<CJApplicationContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    auto appInfo = context->GetApplicationInfo();
    CApplicationInfo* buffer = static_cast<CApplicationInfo*>(malloc(sizeof(CApplicationInfo)));
    if (buffer == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "malloc appinfo fail");
        return nullptr;
    }
    buffer->name = CreateCStringFromString(appInfo->name);
    buffer->bundleName = CreateCStringFromString(appInfo->bundleName);
    return buffer;
}

int32_t FFICJApplicationContextOnOn(int64_t id, char* type,
    void (*cfgCallback)(CConfiguration), void (*memCallback)(int32_t), int32_t *errCode)
{
    auto context = FFI::FFIData::GetData<CJApplicationContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return -1;
    }
    auto typeString = std::string(type);
    if (typeString == "environment") {
        return context->OnOnEnvironment(cfgCallback, memCallback, false, errCode);
    } else {
        TAG_LOGE(AAFwkTag::CONTEXT, "on function type not match");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return -1;
    }
}

void FFICJApplicationContextOnOff(int64_t id, char* type, int32_t callbackId, int32_t *errCode)
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
    } else {
        TAG_LOGE(AAFwkTag::CONTEXT, "off function type not match");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return;
    }
}
}
}
}