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

std::vector<std::shared_ptr<CjAbilityLifecycleCallback>> CJApplicationContext::callbacks_;
CJApplicationContext* CJApplicationContext::cjApplicationContext_ = nullptr;

CJApplicationContext* CJApplicationContext::GetCJApplicationContext(
    std::weak_ptr<AbilityRuntime::ApplicationContext> &&applicationContext)
{
    if (cjApplicationContext_) {
        return cjApplicationContext_;
    }
    cjApplicationContext_ = FFIData::Create<CJApplicationContext>(applicationContext);
    return cjApplicationContext_;
}

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

bool CJApplicationContext::IsAbilityLifecycleCallbackEmpty()
{
    std::lock_guard<std::recursive_mutex> lock(callbackLock_);
    return callbacks_.empty();
}

void CJApplicationContext::RegisterAbilityLifecycleCallback(
    const std::shared_ptr<CjAbilityLifecycleCallback> &abilityLifecycleCallback)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    if (abilityLifecycleCallback == nullptr) {
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(callbackLock_);
    callbacks_.push_back(abilityLifecycleCallback);
}

void CJApplicationContext::UnregisterAbilityLifecycleCallback(
    const std::shared_ptr<CjAbilityLifecycleCallback> &abilityLifecycleCallback)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    std::lock_guard<std::recursive_mutex> lock(callbackLock_);
    auto it = std::find(callbacks_.begin(), callbacks_.end(), abilityLifecycleCallback);
    if (it != callbacks_.end()) {
        callbacks_.erase(it);
    }
}

void CJApplicationContext::DispatchOnAbilityCreate(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    if (!ability) {
        TAG_LOGE(AAFwkTag::CONTEXT, "ability is null");
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(callbackLock_);
    for (auto callback : callbacks_) {
        if (callback != nullptr) {
            callback->OnAbilityCreate(ability);
        }
    }
}

void CJApplicationContext::DispatchOnWindowStageCreate(const int64_t &ability, WindowStagePtr windowStage)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    if (!ability || !windowStage) {
        TAG_LOGE(AAFwkTag::CONTEXT, "ability or windowStage is nullptr");
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(callbackLock_);
    for (auto callback : callbacks_) {
        if (callback != nullptr) {
            callback->OnWindowStageCreate(ability, windowStage);
        }
    }
}

void CJApplicationContext::DispatchWindowStageFocus(const int64_t &ability, WindowStagePtr windowStage)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    if (!ability || !windowStage) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability or windowStage is null");
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(callbackLock_);
    for (auto callback : callbacks_) {
        if (callback != nullptr) {
            callback->OnWindowStageActive(ability, windowStage);
        }
    }
}

void CJApplicationContext::DispatchWindowStageUnfocus(const int64_t &ability, WindowStagePtr windowStage)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    if (!ability || !windowStage) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability or windowStage is nullptr");
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(callbackLock_);
    for (auto callback : callbacks_) {
        if (callback != nullptr) {
            callback->OnWindowStageInactive(ability, windowStage);
        }
    }
}

void CJApplicationContext::DispatchOnWindowStageDestroy(const int64_t &ability, WindowStagePtr windowStage)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    if (!ability || !windowStage) {
        TAG_LOGE(AAFwkTag::CONTEXT, "ability or windowStage is nullptr");
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(callbackLock_);
    for (auto callback : callbacks_) {
        if (callback != nullptr) {
            callback->OnWindowStageDestroy(ability, windowStage);
        }
    }
}

void CJApplicationContext::DispatchOnAbilityDestroy(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    if (!ability) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability is null");
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(callbackLock_);
    for (auto callback : callbacks_) {
        if (callback != nullptr) {
            callback->OnAbilityDestroy(ability);
        }
    }
}

void CJApplicationContext::DispatchOnAbilityForeground(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    if (!ability) {
        TAG_LOGE(AAFwkTag::CONTEXT, "ability is null");
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(callbackLock_);
    for (auto callback : callbacks_) {
        if (callback != nullptr) {
            callback->OnAbilityForeground(ability);
        }
    }
}

void CJApplicationContext::DispatchOnAbilityBackground(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    if (!ability) {
        TAG_LOGE(AAFwkTag::CONTEXT, "ability is null");
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(callbackLock_);
    for (auto callback : callbacks_) {
        if (callback != nullptr) {
            callback->OnAbilityBackground(ability);
        }
    }
}

void CJApplicationContext::DispatchOnAbilityContinue(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    if (!ability) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability is null");
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(callbackLock_);
    for (auto callback : callbacks_) {
        if (callback != nullptr) {
            callback->OnAbilityContinue(ability);
        }
    }
}

void CJApplicationContext::DispatchOnAbilityWillCreate(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    if (!ability) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability is null");
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(callbackLock_);
    for (auto callback : callbacks_) {
        if (callback != nullptr) {
            callback->OnAbilityWillCreate(ability);
        }
    }
}

void CJApplicationContext::DispatchOnWindowStageWillCreate(const int64_t &ability, WindowStagePtr windowStage)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    if (!ability || !windowStage) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability or windowStage is null");
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(callbackLock_);
    for (auto callback : callbacks_) {
        if (callback != nullptr) {
            callback->OnWindowStageWillCreate(ability, windowStage);
        }
    }
}

void CJApplicationContext::DispatchOnWindowStageWillDestroy(const int64_t &ability, WindowStagePtr windowStage)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    if (!ability || !windowStage) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability or windowStage is null");
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(callbackLock_);
    for (auto callback : callbacks_) {
        if (callback != nullptr) {
            callback->OnWindowStageWillDestroy(ability, windowStage);
        }
    }
}

void CJApplicationContext::DispatchOnAbilityWillDestroy(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    if (!ability) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability is null");
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(callbackLock_);
    for (auto callback : callbacks_) {
        if (callback != nullptr) {
            callback->OnAbilityWillDestroy(ability);
        }
    }
}

void CJApplicationContext::DispatchOnAbilityWillForeground(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    if (!ability) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability is null");
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(callbackLock_);
    for (auto callback : callbacks_) {
        if (callback != nullptr) {
            callback->OnAbilityWillForeground(ability);
        }
    }
}

void CJApplicationContext::DispatchOnAbilityWillBackground(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    if (!ability) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability is null");
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(callbackLock_);
    for (auto callback : callbacks_) {
        if (callback != nullptr) {
            callback->OnAbilityWillBackground(ability);
        }
    }
}

void CJApplicationContext::DispatchOnNewWant(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    if (!ability) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability is null");
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(callbackLock_);
    for (auto callback : callbacks_) {
        if (callback != nullptr) {
            callback->OnNewWant(ability);
        }
    }
}

void CJApplicationContext::DispatchOnWillNewWant(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    if (!ability) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability is null");
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(callbackLock_);
    for (auto callback : callbacks_) {
        if (callback != nullptr) {
            callback->OnWillNewWant(ability);
        }
    }
}

void CJApplicationContext::DispatchOnAbilityWillContinue(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "Dispatch onAbilityWillContinue");
    if (!ability) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability is null");
        return;
    }

    std::lock_guard<std::recursive_mutex> lock(callbackLock_);
    for (auto callback : callbacks_) {
        if (callback != nullptr) {
            callback->OnAbilityWillContinue(ability);
        }
    }
}

void CJApplicationContext::DispatchOnWindowStageWillRestore(const int64_t &ability, WindowStagePtr windowStage)
{
    TAG_LOGD(AAFwkTag::APPKIT, "Dispatch onWindowStageWillRestore");
    if (!ability || windowStage == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability or windowStage is null");
        return;
    }

    std::lock_guard<std::recursive_mutex> lock(callbackLock_);
    for (auto callback : callbacks_) {
        if (callback != nullptr) {
            callback->OnWindowStageWillRestore(ability, windowStage);
        }
    }
}

void CJApplicationContext::DispatchOnWindowStageRestore(const int64_t &ability, WindowStagePtr windowStage)
{
    TAG_LOGD(AAFwkTag::APPKIT, "Dispatch onWindowStageRestore");
    if (!ability || windowStage == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability or windowStage is null");
        return;
    }

    std::lock_guard<std::recursive_mutex> lock(callbackLock_);
    for (auto callback : callbacks_) {
        if (callback != nullptr) {
            callback->OnWindowStageRestore(ability, windowStage);
        }
    }
}

void CJApplicationContext::DispatchOnAbilityWillSaveState(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "Dispatch onAbilityWillSaveState");
    if (!ability) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability is null");
        return;
    }

    std::lock_guard<std::recursive_mutex> lock(callbackLock_);
    for (auto callback : callbacks_) {
        if (callback != nullptr) {
            callback->OnAbilityWillSaveState(ability);
        }
    }
}

void CJApplicationContext::DispatchOnAbilitySaveState(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    if (!ability) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability is null");
        return;
    }

    std::lock_guard<std::recursive_mutex> lock(callbackLock_);
    for (auto callback : callbacks_) {
        if (callback != nullptr) {
            callback->OnAbilitySaveState(ability);
        }
    }
}

int32_t CJApplicationContext::OnOnEnvironment(void (*cfgCallback)(CConfiguration),
    void (*memCallback)(int32_t), bool isSync, int32_t *errCode)
{
    auto context = applicationContext_.lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return -1;
    }
    if (envCallback_ != nullptr) {
        TAG_LOGD(AAFwkTag::CONTEXT, "envCallback_ is not nullptr.");
        return envCallback_->Register(CJLambda::Create(cfgCallback), CJLambda::Create(memCallback), isSync);
    }
    envCallback_ = std::make_shared<CjEnvironmentCallback>();
    int32_t callbackId = envCallback_->Register(CJLambda::Create(cfgCallback), CJLambda::Create(memCallback), isSync);
    context->RegisterEnvironmentCallback(envCallback_);
    TAG_LOGD(AAFwkTag::CONTEXT, "OnOnEnvironment is end");
    return callbackId;
}

int32_t CJApplicationContext::OnOnAbilityLifecycle(CArrI64 cFuncIds, bool isSync, int32_t *errCode)
{
    auto context = applicationContext_.lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return -1;
    }
    if (callback_ != nullptr) {
        TAG_LOGD(AAFwkTag::CONTEXT, "callback_ is not nullptr.");
        return callback_->Register(cFuncIds, isSync);
    }
    callback_ = std::make_shared<CjAbilityLifecycleCallback>();
    int32_t callbackId = callback_->Register(cFuncIds, isSync);
    RegisterAbilityLifecycleCallback(callback_);
    return callbackId;
}

int32_t CJApplicationContext::OnOnApplicationStateChange(void (*foregroundCallback)(void),
    void (*backgroundCallback)(void), int32_t *errCode)
{
    auto context = applicationContext_.lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return -1;
    }
    std::lock_guard<std::mutex> lock(applicationStateCallbackLock_);
    if (applicationStateCallback_ != nullptr) {
        return applicationStateCallback_->Register(CJLambda::Create(foregroundCallback),
            CJLambda::Create(backgroundCallback));
    }
    applicationStateCallback_ = std::make_shared<CjApplicationStateChangeCallback>();
    int32_t callbackId = applicationStateCallback_->Register(CJLambda::Create(foregroundCallback),
        CJLambda::Create(backgroundCallback));
    context->RegisterApplicationStateChangeCallback(applicationStateCallback_);
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
        TAG_LOGD(AAFwkTag::CONTEXT, "env_callback is not nullptr.");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return;
    }
    TAG_LOGD(AAFwkTag::CONTEXT, "OnOffEnvironment begin");
    if (!env_callback->UnRegister(callbackId, false)) {
        TAG_LOGE(AAFwkTag::CONTEXT, "call UnRegister failed");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return;
    }
}

void CJApplicationContext::OnOffAbilityLifecycle(int32_t callbackId, int32_t *errCode)
{
    auto context = applicationContext_.lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return;
    }
    std::weak_ptr<CjAbilityLifecycleCallback> callbackWeak(callback_);
    auto lifecycle_callback = callbackWeak.lock();
    if (lifecycle_callback == nullptr) {
        TAG_LOGD(AAFwkTag::CONTEXT, "env_callback is not nullptr.");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return;
    }
    TAG_LOGD(AAFwkTag::CONTEXT, "OnOffAbilityLifecycle begin");
    if (!lifecycle_callback->UnRegister(callbackId, false)) {
        TAG_LOGE(AAFwkTag::CONTEXT, "call UnRegister failed");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return;
    }
}

void CJApplicationContext::OnOffApplicationStateChange(int32_t callbackId, int32_t *errCode)
{
    auto context = applicationContext_.lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return;
    }
    std::lock_guard<std::mutex> lock(applicationStateCallbackLock_);
    if (applicationStateCallback_ == nullptr) {
        TAG_LOGD(AAFwkTag::CONTEXT, "env_callback is not nullptr.");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return;
    }
    TAG_LOGD(AAFwkTag::CONTEXT, "OnOffApplicationStateChange begin");
    if (!applicationStateCallback_->UnRegister(callbackId)) {
        TAG_LOGE(AAFwkTag::CONTEXT, "call UnRegister failed");
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return;
    }
    if (applicationStateCallback_->IsEmpty()) {
        applicationStateCallback_.reset();
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

void FfiCJApplicationContextOnOff(int64_t id, const char* type, int32_t callbackId, int32_t *errCode)
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
}
}
}