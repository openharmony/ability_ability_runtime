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

#include "stage_context_transfer.h"

#include "ani_base_context.h"
#include "ets_ability_stage_context.h"
#include "ets_context_utils.h"
#include "ets_runtime.h"
#include "hitrace_meter.h"
#include "js_ability_stage_context.h"
#include "js_runtime_utils.h"
#include "hilog_tag_wrapper.h"
#include "napi_base_context.h"

namespace OHOS {
namespace AbilityRuntime {
StageContextTransfer &StageContextTransfer::GetInstance()
{
    static StageContextTransfer instance;
    return instance;
}

ani_ref StageContextTransfer::GetStaticRef(ETSRuntime &etsRuntime, std::shared_ptr<NativeReference> contextRef)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto &jsRuntimePtr = etsRuntime.GetJsRuntime();
    if (jsRuntimePtr == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "jsRuntime is null");
        return nullptr;
    }
    auto &jsRuntime = static_cast<JsRuntime &>(*jsRuntimePtr);
    auto stageContext = UnwrapContext(jsRuntime.GetNapiEnv(), contextRef);
    return GetStaticRef(etsRuntime.GetAniEnv(), stageContext);
}

ani_ref StageContextTransfer::GetStaticRef(ani_env *aniEnv, std::shared_ptr<Context> stageContext)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (aniEnv == nullptr || stageContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "aniEnv or context is null");
        return nullptr;
    }
    auto &bindingObj = stageContext->GetBindingObject();
    if (bindingObj == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null bindingObj");
        return nullptr;
    }
    auto contextRef = bindingObj->Get<ani_ref>();
    if (contextRef != nullptr) {
        TAG_LOGD(AAFwkTag::CONTEXT, "there exist a staticRef");
        return *contextRef;
    }

    if (ETSAbilityStageContext::CreateEtsAbilityStageContext(aniEnv, stageContext) == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "Failed to create contextObj");
        return nullptr;
    }
    ani_ref *aniRefPtr = bindingObj->Get<ani_ref>();
    if (aniRefPtr == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "aniRefPtr null");
        return nullptr;
    }
    return *aniRefPtr;
}

NativeReference *StageContextTransfer::GetDynamicRef(ETSRuntime &etsRuntime, ani_ref contextRef)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto &jsRuntimePtr = etsRuntime.GetJsRuntime();
    if (jsRuntimePtr == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "jsRuntime is null");
        return nullptr;
    }
    auto &jsRuntime = static_cast<JsRuntime &>(*jsRuntimePtr);
    auto stageContext = UnwrapContext(etsRuntime.GetAniEnv(), contextRef);
    return GetDynamicRef(jsRuntime.GetNapiEnv(), stageContext);
}

NativeReference *StageContextTransfer::GetDynamicRef(napi_env napiEnv, std::shared_ptr<Context> stageContext)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (napiEnv == nullptr || stageContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "napiEnv or context is null");
        return nullptr;
    }
    auto &bindingObj = stageContext->GetBindingObject();
    if (bindingObj == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null bindingObj");
        return nullptr;
    }
    auto contextRef = bindingObj->Get<NativeReference>();
    if (contextRef != nullptr) {
        TAG_LOGD(AAFwkTag::CONTEXT, "there exist a dynamicRef");
        return contextRef;
    }

    auto nativeRefPtr = CreateNativeReference(napiEnv, stageContext);
    if (nativeRefPtr == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "Failed to create nativeRefPtr");
        return nullptr;
    }
    NativeReference *nativeRef = nativeRefPtr.release();
    stageContext->Bind(nativeRef);
    return nativeRef;
}

void StageContextTransfer::SaveContextRef(const std::string &moduleName, std::shared_ptr<NativeReference> contextRef)
{
    TAG_LOGI(AAFwkTag::CONTEXT, "Save contextRef:%{public}s", moduleName.c_str());
    std::lock_guard<std::mutex> lock(contextRefMapMutex_);
    contextRefMap_[moduleName] = contextRef;
}

std::shared_ptr<NativeReference> StageContextTransfer::GetContextRef(const std::string &moduleName)
{
    std::lock_guard<std::mutex> lock(contextRefMapMutex_);
    return contextRefMap_[moduleName];
}

std::shared_ptr<Context> StageContextTransfer::UnwrapContext(napi_env napiEnv,
    std::shared_ptr<NativeReference> contextRef)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (napiEnv == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null napiEnv");
        return nullptr;
    }
    if (contextRef == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null contextRef");
        return nullptr;
    }
    napi_value contextValue = contextRef->GetNapiValue();
    if (!CheckTypeForNapiValue(napiEnv, contextValue, napi_object)) {
        TAG_LOGE(AAFwkTag::CONTEXT, "contextValue is not napi_object");
        return nullptr;
    }
    return AbilityRuntime::GetStageModeContext(napiEnv, contextValue);
}

std::shared_ptr<Context> StageContextTransfer::UnwrapContext(ani_env *aniEnv, ani_ref contextRef)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null aniEnv");
        return nullptr;
    }
    if (contextRef == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null contextRef");
        return nullptr;
    }
    ani_object contextObj = reinterpret_cast<ani_object>(contextRef);
    return AbilityRuntime::GetStageModeContext(aniEnv, contextObj);
}

std::unique_ptr<NativeReference> StageContextTransfer::CreateNativeReference(napi_env napiEnv,
    std::shared_ptr<Context> stageContext)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (napiEnv == nullptr || stageContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null param");
        return nullptr;
    }

    auto value = CreateJsAbilityStageContext(napiEnv, stageContext);
    auto systemModule = JsRuntime::LoadSystemModuleByEngine(napiEnv, "application.AbilityStageContext", &value, 1);
    if (systemModule == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null systemModule");
        return nullptr;
    }

    napi_value object = systemModule->GetNapiValue();
    if (!CheckTypeForNapiValue(napiEnv, object, napi_object)) {
        TAG_LOGE(AAFwkTag::CONTEXT, "check type failed");
        return nullptr;
    }

    auto workContext = new (std::nothrow) std::weak_ptr<Context>(stageContext);
    if (workContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null workContext");
        return nullptr;
    }
    auto status = napi_coerce_to_native_binding_object(napiEnv, object, DetachCallbackFunc, AttachAbilityStageContext,
        workContext, nullptr);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::CONTEXT, "coerce AbilityStageContext failed: %{public}d", status);
        delete workContext;
        return nullptr;
    }

    status = napi_wrap(napiEnv, object, workContext,
        [](napi_env, void *data, void *) {
            TAG_LOGD(AAFwkTag::CONTEXT, "finalizer for weak_ptr AbilityStageContext");
            delete static_cast<std::weak_ptr<Context> *>(data);
        }, nullptr, nullptr);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::CONTEXT, "wrap failed: %{public}d", status);
        delete workContext;
        return nullptr;
    }

    return systemModule;
}
} // namespace AbilityRuntime
} // namespace OHOS