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
 
#include "ani_common_util.h"
#include "context_transfer.h"
#include "interop_js/arkts_esvalue.h"
#include "interop_js/arkts_interop_js_api.h"
#include "interop_js/hybridgref_ani.h"
#include "interop_js/hybridgref_napi.h"
#include "js_runtime.h"
 
namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char* ETS_EVENT_HUB_CLASS_NAME = "application.EventHub.EventHub";
}
 
std::shared_ptr<Context> EventHub::GetContext(ani_env *env, ani_object aniObj)
{
    ani_long nativeContextLong = 0;
    ani_class cls {};
    ani_field contextField = nullptr;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return nullptr;
    }
    if ((status = env->FindClass(ETS_EVENT_HUB_CLASS_NAME, &cls)) != ANI_OK) {
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
    auto weakContext = reinterpret_cast<std::weak_ptr<Context>*>(nativeContextLong);
    return weakContext != nullptr ? weakContext->lock() : nullptr;
}

bool EventHub::GetIsApplicationContext(ani_env *env, ani_object aniObj)
{
    ani_boolean isApplicationContext = false;
    ani_class cls {};
    ani_field contextField = nullptr;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return false;
    }
    if ((status = env->FindClass(ETS_EVENT_HUB_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status: %{public}d", status);
        return false;
    }
    if ((status = env->Class_FindField(cls, "isApplicationContext", &contextField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status: %{public}d", status);
        return false;
    }
    if ((status = env->Object_GetField_Boolean(aniObj, contextField, &isApplicationContext)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status: %{public}d", status);
        return false;
    }
    return isApplicationContext;
}
 
ani_object EventHub::GetDynamicContextEventHub(ani_env *aniEnv, ani_object aniObj)
{
    TAG_LOGI(AAFwkTag::APPKIT, "GetDynamicContextEventHub called");
    if (aniEnv == nullptr || aniObj == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "aniEnv or aniObj is null");
        return nullptr;
    }
    auto context = GetContext(aniEnv, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        return nullptr;
    }
    ani_class contextCls = nullptr;
    auto status = aniEnv->FindClass("application.Context.Context", &contextCls);
    if (status != ANI_OK || contextCls == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "status: %{public}d", status);
        return nullptr;
    }
    auto isApplicationContext = GetIsApplicationContext(aniEnv, aniObj);
    std::string contextType = isApplicationContext ? "ApplicationContext" : "Context";
    ani_object staticResult = nullptr;
    {
        napi_env napiEnv = {};
        if (!arkts_napi_scope_open(aniEnv, &napiEnv)) {
            TAG_LOGE(AAFwkTag::APPKIT, "arkts_napi_scope_open failed");
            return nullptr;
        }
        auto contextObj = ContextTransfer::GetInstance().GetDynamicObject(contextType, napiEnv, context);
        if (contextObj == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "GetDynamicContext failed");
            arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr);
            return nullptr;
        }
        napi_value eventHub = nullptr;
        if (napi_get_named_property(napiEnv, contextObj, "eventHub", &eventHub) != napi_ok) {
            TAG_LOGE(AAFwkTag::APPKIT, "napi_get_named_property failed");
            return nullptr;
        }
        if (eventHub == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "napi_get_named_property failed, eventHub nullptr");
            return nullptr;
        }
        if (!CallNapiSetNativeEventHubRefFn(aniEnv, aniObj, napiEnv, eventHub)) {
            TAG_LOGE(AAFwkTag::APPKIT, "CallNapiSetNativeEventHubRefFn failed");
            return nullptr;
        }
        hybridgref dynamicHybrigRef = nullptr;
        if (!hybridgref_create_from_napi(napiEnv, contextObj, &dynamicHybrigRef)) {
            TAG_LOGE(AAFwkTag::APPKIT, "hybridgref_create_from_napi failed");
            return nullptr;
        }
        if (!hybridgref_get_esvalue(aniEnv, dynamicHybrigRef, &staticResult)) {
            TAG_LOGE(AAFwkTag::APPKIT, "hybridgref_get_esvalue failed");
            hybridgref_delete_from_napi(napiEnv, dynamicHybrigRef);
            return nullptr;
        }
        hybridgref_delete_from_napi(napiEnv, dynamicHybrigRef);
        if (!arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr)) {
            TAG_LOGE(AAFwkTag::APPKIT, "arkts_napi_scope_close_n failed");
            return nullptr;
        }
    }
    return staticResult;
}
 
bool EventHub::CallNapiSetNativeEventHubRefFn(ani_env *aniEnv, ani_object aniObj, napi_env napiEnv,
    napi_value eventHub)
{
    napi_value setNativeEventHubRefFn = nullptr;
    if (napi_get_named_property(napiEnv, eventHub, "setNativeEventHubRef", &setNativeEventHubRefFn) != napi_ok) {
        TAG_LOGE(AAFwkTag::APPKIT, "napi_get_named_property failed");
        return false;
    }
    if (setNativeEventHubRefFn == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null method: setNativeEventHubRef");
        return false;
    }
    hybridgref nativeHybrigRef = nullptr;
    if (!hybridgref_create_from_ani(aniEnv, static_cast<ani_ref>(aniObj), &nativeHybrigRef)) {
        TAG_LOGE(AAFwkTag::APPKIT, "hybridgref_create_from_ani failed");
        return false;
    }
    napi_value nativeEventHubRef {};
    if (!hybridgref_get_napi_value(napiEnv, nativeHybrigRef, &nativeEventHubRef)) {
        TAG_LOGE(AAFwkTag::APPKIT, "hybridgref_get_napi_value failed");
        hybridgref_delete_from_ani(aniEnv, nativeHybrigRef);
        return false;
    }
    hybridgref_delete_from_ani(aniEnv, nativeHybrigRef);
    napi_value dynamicResult;
    napi_status status = napi_call_function(napiEnv, eventHub, setNativeEventHubRefFn, 1, &nativeEventHubRef,
        &dynamicResult);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::APPKIT, "napi_call_function failed");
        return false;
    }
    return true;
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
        ani_native_function {"getDynamicContextEventHub", ":C{std.interop.ESValue}",
            reinterpret_cast<void *>(GetDynamicContextEventHub)},
    };
    aniEnv->Class_BindNativeMethods(contextCls, contextFunctions.data(),
        contextFunctions.size());
}
}
}