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
 
#include "event_hub.h"
 
namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char* ETS_EVENT_HUB_CLASS_NAME = "Lapplication/EventHub/EventHub;";
constexpr const char* ETS_CONTEXT_CLASS_NAME = "Lapplication/Context/Context;";
}
 
std::shared_ptr<AbilityContext> EventHub::GetAbilityContext(ani_env *env, ani_object aniObj)
{
    ani_long nativeContextLong;
    ani_class cls {};
    ani_field contextField = nullptr;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return nullptr;
    }
    if ((status = env->FindClass(ETS_CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindField(cls, "nativeContext", &contextField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_GetField_Long(aniObj, contextField, &nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status: %{public}d", status);
        return nullptr;
    }
    auto weakContext = reinterpret_cast<std::weak_ptr<AbilityContext>*>(nativeContextLong);
    return weakContext != nullptr ? weakContext->lock() : nullptr;
}
 
ani_object EventHub::GetDynamicContextEventHub([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj)
{
    TAG_LOGI(AAFwkTag::APPKIT, "GetDynamicContextEventHub called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return nullptr;
    }
    ani_ref nativeContextRef;
    ani_status status = ANI_ERROR;
    if ((status = env->Object_GetFieldByName_Ref(aniObj, "context", &nativeContextRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status: %{public}d", status);
        return nullptr;
    }
    if (nativeContextRef == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        return nullptr;
    }
    auto context = GetAbilityContext(env, static_cast<ani_object>(nativeContextRef));
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        return nullptr;
    }
    auto &bindingObj = context->GetBindingObject();
    if (bindingObj == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null bindingObj");
        return nullptr;
    }
    auto dynamicContext = bindingObj->Get<NativeReference>();
    if (dynamicContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null dynamicContext");
        return nullptr;
    }
    JsRuntime *jsRuntime = JsRuntime::GetInstance();
    if (jsRuntime == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null jsRuntime");
        return nullptr;
    }
    napi_env napiEnv = jsRuntime->GetNapiEnv();
    napi_value eventHub = nullptr;
    napi_get_named_property(napiEnv, dynamicContext->Get(), "eventHub", &eventHub);
    if (eventHub == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "napi_get_named_property failed, eventHub nullptr");
        return nullptr;
    }
    napi_value setNativeEventHubRefFn = nullptr;
    napi_get_named_property(napiEnv, eventHub, "setNativeEventHubRef", &setNativeEventHubRefFn);
    if (setNativeEventHubRefFn == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null method: setNativeEventHubRef");
        return nullptr;
    }
    hybridgref nativeHybrigRef = nullptr;
    bool success = hybridgref_create_from_ani(env, static_cast<ani_ref>(aniObj), &nativeHybrigRef);
    if (!success) {
        TAG_LOGE(AAFwkTag::APPKIT, "hybridgref_create_from_ani failed");
        return nullptr;
    }
    napi_value nativeEventHubRef {};
    if (!hybridgref_get_napi_value(napiEnv, nativeHybrigRef, &nativeEventHubRef)) {
        TAG_LOGE(AAFwkTag::APPKIT, "hybridgref_get_napi_vlaue failed");
        hybridgref_delete_from_ani(env, nativeHybrigRef);
        return nullptr;
    }
    hybridgref_delete_from_ani(env, nativeHybrigRef);
    napi_value dynamicResult;
    napi_call_function(napiEnv, eventHub, setNativeEventHubRefFn, 1, &nativeEventHubRef, &dynamicResult);
    hybridgref dynamicHybrigRef = nullptr;
    success = hybridgref_create_from_napi(napiEnv, dynamicContext->Get(), &dynamicHybrigRef);
    if (!success) {
        TAG_LOGE(AAFwkTag::APPKIT, "hybridgref_create_from_napi failed");
        return nullptr;
    }
    ani_object staticResult;
    success = hybridgref_get_esvalue(env, dynamicHybrigRef, &staticResult);
    if (!success) {
        TAG_LOGE(AAFwkTag::APPKIT, "hybridgref_get_esvalue failed");
        hybridgref_delete_from_napi(napiEnv, dynamicHybrigRef);
        return nullptr;
    }
    hybridgref_delete_from_napi(napiEnv, dynamicHybrigRef);
    return staticResult;
}
 
void EventHub::InitAniEventHub(ani_env *aniEnv)
{
    TAG_LOGI(AAFwkTag::APPKIT, "called");
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    ani_class contextCls = nullptr;
    if (aniEnv->FindClass(ETS_EVENT_HUB_CLASS_NAME, &contextCls) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "FindClass Context failed");
        return;
    }
    std::array contextFunctions = {
        ani_native_function {"getDynamicContextEventHub", ":Lstd/interop/ESValue;",
            reinterpret_cast<void *>(GetDynamicContextEventHub)},
    };
    aniEnv->Class_BindNativeMethods(contextCls, contextFunctions.data(),
        contextFunctions.size());
}

void EventHub::SetEventHubContext(ani_env *aniEnv, ani_ref eventHubRef, ani_ref contextRef)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_class contextCls = nullptr;
    if (aniEnv->FindClass(ETS_EVENT_HUB_CLASS_NAME, &contextCls) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "FindClass Context failed");
        return;
    }
    ani_field contextField;
    if ((status = aniEnv->Class_FindField(contextCls, "context", &contextField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_FindField failed status: %{public}d", status);
        return;
    }
    if ((status = aniEnv->Object_SetField_Ref(static_cast<ani_object>(eventHubRef), contextField,
        contextRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetField_Long failed status: %{public}d", status);
        return;
    }
}

}
}