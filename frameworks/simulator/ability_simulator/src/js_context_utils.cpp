/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "js_context_utils.h"

#include <iostream>

#include "ability_runtime_error_util.h"
#include "context_impl.h"
#include "hilog_tag_wrapper.h"
#include "js_application_context_utils.h"
#include "js_data_converter.h"
#include "js_error_utils.h"
#include "js_resource_manager_utils.h"
#include "js_runtime_utils.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr char BASE_CONTEXT_NAME[] = "__base_context_ptr__";

void *DetachNewBaseContext(napi_env, void *nativeObject, void *)
{
    auto *origContext = static_cast<std::weak_ptr<Context> *>(nativeObject);
    if (origContext == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "origContext is null");
        return nullptr;
    }
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "New detached base context");
    auto *detachNewContext = new (std::nothrow) std::weak_ptr<Context>(*origContext);
    return detachNewContext;
}

void DetachFinalizeBaseContext(void *detachedObject, void *)
{
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "Finalizer detached base context");
    delete static_cast<std::weak_ptr<Context> *>(detachedObject);
}

class JsBaseContext {
public:
    explicit JsBaseContext(std::weak_ptr<Context> &&context) : context_(std::move(context)) {}
    virtual ~JsBaseContext() = default;

    static void Finalizer(napi_env env, void *data, void *hint);
    static napi_value CreateBundleContext(napi_env env, napi_callback_info info);
    static napi_value GetApplicationContext(napi_env env, napi_callback_info info);
    static napi_value SwitchArea(napi_env env, napi_callback_info info);
    static napi_value GetArea(napi_env env, napi_callback_info info);
    static napi_value CreateModuleContext(napi_env env, napi_callback_info info);
    static napi_value CreateModuleResourceManager(napi_env env, napi_callback_info info);

    static napi_value GetCacheDir(napi_env env, napi_callback_info info);
    static napi_value GetTempDir(napi_env env, napi_callback_info info);
    static napi_value GetResourceDir(napi_env env, napi_callback_info info);
    static napi_value GetFilesDir(napi_env env, napi_callback_info info);
    static napi_value GetDistributedFilesDir(napi_env env, napi_callback_info info);
    static napi_value GetDatabaseDir(napi_env env, napi_callback_info info);
    static napi_value GetPreferencesDir(napi_env env, napi_callback_info info);
    static napi_value GetBundleCodeDir(napi_env env, napi_callback_info info);
    static napi_value GetCloudFileDir(napi_env env, napi_callback_info info);

    napi_value OnGetCacheDir(napi_env env, NapiCallbackInfo &info);
    napi_value OnGetTempDir(napi_env env, NapiCallbackInfo &info);
    napi_value OnGetResourceDir(napi_env env, NapiCallbackInfo &info);
    napi_value OnGetFilesDir(napi_env env, NapiCallbackInfo &info);
    napi_value OnGetDistributedFilesDir(napi_env env, NapiCallbackInfo &info);
    napi_value OnGetDatabaseDir(napi_env env, NapiCallbackInfo &info);
    napi_value OnGetPreferencesDir(napi_env env, NapiCallbackInfo &info);
    napi_value OnGetBundleCodeDir(napi_env env, NapiCallbackInfo &info);
    napi_value OnGetCloudFileDir(napi_env env, NapiCallbackInfo &info);
    napi_value OnSwitchArea(napi_env env, NapiCallbackInfo &info);
    napi_value OnGetArea(napi_env env, NapiCallbackInfo &info);
    napi_value OnGetApplicationContext(napi_env env, NapiCallbackInfo &info);

protected:
    std::weak_ptr<Context> context_;

private:
    napi_value CreateJsModuleContext(napi_env env, const std::shared_ptr<Context> &moduleContext);
    napi_value OnCreateModuleContext(napi_env env, NapiCallbackInfo &info);
    bool CheckCallerIsSystemApp();
};

void JsBaseContext::Finalizer(napi_env env, void *data, void *hint)
{
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "called");
    std::unique_ptr<JsBaseContext>(static_cast<JsBaseContext*>(data));
}

napi_value JsBaseContext::CreateBundleContext(napi_env env, napi_callback_info info)
{
    return nullptr;
}

napi_value JsBaseContext::GetApplicationContext(napi_env env, napi_callback_info info)
{
    GET_NAPI_INFO_WITH_NAME_AND_CALL(env, info, JsBaseContext, OnGetApplicationContext, BASE_CONTEXT_NAME);
}

napi_value JsBaseContext::SwitchArea(napi_env env, napi_callback_info info)
{
    GET_NAPI_INFO_WITH_NAME_AND_CALL(env, info, JsBaseContext, OnSwitchArea, BASE_CONTEXT_NAME);
}

napi_value JsBaseContext::OnSwitchArea(napi_env env, NapiCallbackInfo &info)
{
    if (info.argc == 0) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "invalid argc");
        return CreateJsUndefined(env);
    }

    auto context = context_.lock();
    if (!context) {
        TAG_LOGW(AAFwkTag::ABILITY_SIM, "context released");
        return CreateJsUndefined(env);
    }

    int mode = 0;
    if (!ConvertFromJsValue(env, info.argv[0], mode)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "Parse mode failed");
        return CreateJsUndefined(env);
    }

    context->SwitchArea(mode);

    napi_value object = info.thisVar;
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "null object");
        return CreateJsUndefined(env);
    }
    BindNativeProperty(env, object, "cacheDir", GetCacheDir);
    BindNativeProperty(env, object, "tempDir", GetTempDir);
    BindNativeProperty(env, object, "resourceDir", GetResourceDir);
    BindNativeProperty(env, object, "filesDir", GetFilesDir);
    BindNativeProperty(env, object, "distributedFilesDir", GetDistributedFilesDir);
    BindNativeProperty(env, object, "databaseDir", GetDatabaseDir);
    BindNativeProperty(env, object, "preferencesDir", GetPreferencesDir);
    BindNativeProperty(env, object, "bundleCodeDir", GetBundleCodeDir);
    BindNativeProperty(env, object, "cloudFileDir", GetCloudFileDir);
    return CreateJsUndefined(env);
}

napi_value JsBaseContext::CreateModuleContext(napi_env env, napi_callback_info info)
{
    GET_NAPI_INFO_WITH_NAME_AND_CALL(env, info, JsBaseContext, OnCreateModuleContext, BASE_CONTEXT_NAME);
}
napi_value JsBaseContext::OnCreateModuleContext(napi_env env, NapiCallbackInfo &info)
{
    auto context = context_.lock();
    if (!context) {
        TAG_LOGW(AAFwkTag::ABILITY_SIM, "null context");
        AbilityRuntimeErrorUtil::Throw(env, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);
        return CreateJsUndefined(env);
    }
    std::shared_ptr<Context> moduleContext = nullptr;
    std::string moduleName;
    if (!ConvertFromJsValue(env, info.argv[1], moduleName)) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "Parse inner module name");
        if (!ConvertFromJsValue(env, info.argv[0], moduleName)) {
            TAG_LOGE(AAFwkTag::ABILITY_SIM, "Parse moduleName failed");
            ThrowInvalidParamError(env, "Parse param moduleName failed, moduleName must be string.");
            return CreateJsUndefined(env);
        }
        moduleContext = context->CreateModuleContext(moduleName);
    } else {
        std::string bundleName;
        if (!ConvertFromJsValue(env, info.argv[0], bundleName)) {
            TAG_LOGE(AAFwkTag::ABILITY_SIM, "Parse bundleName failed");
            ThrowInvalidParamError(env, "Parse param bundleName failed, bundleName must be string.");
            return CreateJsUndefined(env);
        }
        if (!CheckCallerIsSystemApp()) {
            TAG_LOGE(AAFwkTag::ABILITY_SIM, "not system-app");
            AbilityRuntimeErrorUtil::Throw(env, ERR_ABILITY_RUNTIME_NOT_SYSTEM_APP);
            return CreateJsUndefined(env);
        }
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "Parse outer module name");
        moduleContext = context->CreateModuleContext(bundleName, moduleName);
    }
    if (!moduleContext) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "null moduleContext");
        AbilityRuntimeErrorUtil::Throw(env, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);
        return CreateJsUndefined(env);
    }
    return CreateJsModuleContext(env, moduleContext);
}

napi_value JsBaseContext::CreateJsModuleContext(napi_env env, const std::shared_ptr<Context> &moduleContext)
{
    napi_value value = CreateJsBaseContext(env, moduleContext, true);

    auto systemModule = JsRuntime::LoadSystemModuleByEngine(env, "application.Context", &value, 1);
    if (systemModule == nullptr) {
        TAG_LOGW(AAFwkTag::ABILITY_SIM, "null systemModule");
        AbilityRuntimeErrorUtil::Throw(env, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);
        return CreateJsUndefined(env);
    }
    napi_value object = systemModule->GetNapiValue();
    if (!CheckTypeForNapiValue(env, object, napi_object)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "get object failed");
        AbilityRuntimeErrorUtil::Throw(env, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);
        return CreateJsUndefined(env);
    }
    auto workContext = new (std::nothrow) std::weak_ptr<Context>(moduleContext);
    napi_coerce_to_native_binding_object(env, object, DetachCallbackFunc, AttachBaseContext, workContext, nullptr);
    auto res = napi_wrap(env, object, workContext,
        [](napi_env, void *data, void *) {
            TAG_LOGD(AAFwkTag::ABILITY_SIM, "Finalizer for weak_ptr module context is called");
            delete static_cast<std::weak_ptr<Context> *>(data);
        },
        nullptr, nullptr);
    if (res != napi_ok && workContext != nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "napi_wrap failed:%{public}d", res);
        delete workContext;
        return CreateJsUndefined(env);
    }
    return object;
}

napi_value JsBaseContext::CreateModuleResourceManager(napi_env env, napi_callback_info info)
{
    return nullptr;
}

napi_value JsBaseContext::GetArea(napi_env env, napi_callback_info info)
{
    GET_NAPI_INFO_WITH_NAME_AND_CALL(env, info, JsBaseContext, OnGetArea, BASE_CONTEXT_NAME);
}

napi_value JsBaseContext::OnGetArea(napi_env env, NapiCallbackInfo &info)
{
    auto context = context_.lock();
    if (!context) {
        TAG_LOGW(AAFwkTag::ABILITY_SIM, "context released");
        return CreateJsUndefined(env);
    }
    int area = context->GetArea();
    return CreateJsValue(env, area);
}

napi_value JsBaseContext::GetCacheDir(napi_env env, napi_callback_info info)
{
    GET_NAPI_INFO_WITH_NAME_AND_CALL(env, info, JsBaseContext, OnGetCacheDir, BASE_CONTEXT_NAME);
}

napi_value JsBaseContext::OnGetCacheDir(napi_env env, NapiCallbackInfo &info)
{
    auto context = context_.lock();
    if (!context) {
        TAG_LOGW(AAFwkTag::ABILITY_SIM, "context released");
        return CreateJsUndefined(env);
    }
    std::string path = context->GetCacheDir();
    return CreateJsValue(env, path);
}

napi_value JsBaseContext::GetTempDir(napi_env env, napi_callback_info info)
{
    GET_NAPI_INFO_WITH_NAME_AND_CALL(env, info, JsBaseContext, OnGetTempDir, BASE_CONTEXT_NAME);
}

napi_value JsBaseContext::OnGetTempDir(napi_env env, NapiCallbackInfo &info)
{
    auto context = context_.lock();
    if (!context) {
        TAG_LOGW(AAFwkTag::ABILITY_SIM, "context released");
        return CreateJsUndefined(env);
    }
    std::string path = context->GetTempDir();
    return CreateJsValue(env, path);
}

napi_value JsBaseContext::GetResourceDir(napi_env env, napi_callback_info info)
{
    GET_NAPI_INFO_WITH_NAME_AND_CALL(env, info, JsBaseContext, OnGetResourceDir, BASE_CONTEXT_NAME);
}

napi_value JsBaseContext::OnGetResourceDir(napi_env env, NapiCallbackInfo &info)
{
    auto context = context_.lock();
    if (!context) {
        TAG_LOGW(AAFwkTag::ABILITY_SIM, "context released");
        return CreateJsUndefined(env);
    }
    std::string path = context->GetResourceDir();
    return CreateJsValue(env, path);
}

napi_value JsBaseContext::GetFilesDir(napi_env env, napi_callback_info info)
{
    GET_NAPI_INFO_WITH_NAME_AND_CALL(env, info, JsBaseContext, OnGetFilesDir, BASE_CONTEXT_NAME);
}

napi_value JsBaseContext::OnGetFilesDir(napi_env env, NapiCallbackInfo &info)
{
    auto context = context_.lock();
    if (!context) {
        TAG_LOGW(AAFwkTag::ABILITY_SIM, "context released");
        return CreateJsUndefined(env);
    }
    std::string path = context->GetFilesDir();
    return CreateJsValue(env, path);
}

napi_value JsBaseContext::GetDistributedFilesDir(napi_env env, napi_callback_info info)
{
    GET_NAPI_INFO_WITH_NAME_AND_CALL(env, info, JsBaseContext, OnGetDistributedFilesDir, BASE_CONTEXT_NAME);
}

napi_value JsBaseContext::OnGetDistributedFilesDir(napi_env env, NapiCallbackInfo &info)
{
    auto context = context_.lock();
    if (!context) {
        TAG_LOGW(AAFwkTag::ABILITY_SIM, "context released");
        return CreateJsUndefined(env);
    }
    std::string path = context->GetDistributedFilesDir();
    return CreateJsValue(env, path);
}

napi_value JsBaseContext::GetDatabaseDir(napi_env env, napi_callback_info info)
{
    GET_NAPI_INFO_WITH_NAME_AND_CALL(env, info, JsBaseContext, OnGetDatabaseDir, BASE_CONTEXT_NAME);
}

napi_value JsBaseContext::OnGetDatabaseDir(napi_env env, NapiCallbackInfo &info)
{
    auto context = context_.lock();
    if (!context) {
        TAG_LOGW(AAFwkTag::ABILITY_SIM, "context released");
        return CreateJsUndefined(env);
    }
    std::string path = context->GetDatabaseDir();
    return CreateJsValue(env, path);
}

napi_value JsBaseContext::GetPreferencesDir(napi_env env, napi_callback_info info)
{
    GET_NAPI_INFO_WITH_NAME_AND_CALL(env, info, JsBaseContext, OnGetPreferencesDir, BASE_CONTEXT_NAME);
}

napi_value JsBaseContext::OnGetPreferencesDir(napi_env env, NapiCallbackInfo &info)
{
    auto context = context_.lock();
    if (!context) {
        TAG_LOGW(AAFwkTag::ABILITY_SIM, "context released");
        return CreateJsUndefined(env);
    }
    std::string path = context->GetPreferencesDir();
    return CreateJsValue(env, path);
}

napi_value JsBaseContext::GetBundleCodeDir(napi_env env, napi_callback_info info)
{
    GET_NAPI_INFO_WITH_NAME_AND_CALL(env, info, JsBaseContext, OnGetBundleCodeDir, BASE_CONTEXT_NAME);
}

napi_value JsBaseContext::OnGetBundleCodeDir(napi_env env, NapiCallbackInfo &info)
{
    auto context = context_.lock();
    if (!context) {
        TAG_LOGW(AAFwkTag::ABILITY_SIM, "context released");
        return CreateJsUndefined(env);
    }
    std::string path = context->GetBundleCodeDir();
    return CreateJsValue(env, path);
}

napi_value JsBaseContext::GetCloudFileDir(napi_env env, napi_callback_info info)
{
    GET_NAPI_INFO_WITH_NAME_AND_CALL(env, info, JsBaseContext, OnGetCloudFileDir, BASE_CONTEXT_NAME);
}

napi_value JsBaseContext::OnGetCloudFileDir(napi_env env, NapiCallbackInfo &info)
{
    auto context = context_.lock();
    if (!context) {
        TAG_LOGW(AAFwkTag::ABILITY_SIM, "context released");
        return CreateJsUndefined(env);
    }
    std::string path = context->GetCloudFileDir();
    return CreateJsValue(env, path);
}

napi_value JsBaseContext::OnGetApplicationContext(napi_env env, NapiCallbackInfo &info)
{
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "called");
    napi_value value = JsApplicationContextUtils::CreateJsApplicationContext(env, context_.lock());
    auto systemModule = JsRuntime::LoadSystemModuleByEngine(env, "application.ApplicationContext", &value, 1);
    if (systemModule == nullptr) {
        return CreateJsUndefined(env);
    }
    auto contextObj =  systemModule->GetNapiValue();
    return contextObj;
}

bool JsBaseContext::CheckCallerIsSystemApp()
{
    return true;
}
} // namespace

napi_value CreateJsBaseContext(napi_env env, std::shared_ptr<Context> context, bool keepContext)
{
    napi_value object = nullptr;
    napi_create_object(env, &object);
    if (object == nullptr) {
        TAG_LOGW(AAFwkTag::ABILITY_SIM, "null object");
        return object;
    }

    auto appInfo = context->GetApplicationInfo();
    if (appInfo != nullptr) {
        napi_set_named_property(env, object, "applicationInfo", CreateJsApplicationInfo(env, *appInfo));
    }
    auto hapModuleInfo = context->GetHapModuleInfo();
    if (hapModuleInfo != nullptr) {
        napi_set_named_property(env, object, "currentHapModuleInfo", CreateJsHapModuleInfo(env, *hapModuleInfo));
    }

    auto resourceManager = context->GetResourceManager();
    if (resourceManager != nullptr) {
        auto jsResourceManager = CreateJsResourceManager(env, resourceManager, context);
        if (jsResourceManager != nullptr) {
            napi_set_named_property(env, object, "resourceManager", jsResourceManager);
        } else {
            TAG_LOGE(AAFwkTag::ABILITY_SIM, "null jsResourceManager");
        }
    }

    auto jsContext = std::make_unique<JsBaseContext>(context);
    SetNamedNativePointer(env, object, BASE_CONTEXT_NAME, jsContext.release(), JsBaseContext::Finalizer);

    BindNativeProperty(env, object, "cacheDir", JsBaseContext::GetCacheDir);
    BindNativeProperty(env, object, "tempDir", JsBaseContext::GetTempDir);
    BindNativeProperty(env, object, "resourceDir", JsBaseContext::GetResourceDir);
    BindNativeProperty(env, object, "filesDir", JsBaseContext::GetFilesDir);
    BindNativeProperty(env, object, "distributedFilesDir", JsBaseContext::GetDistributedFilesDir);
    BindNativeProperty(env, object, "databaseDir", JsBaseContext::GetDatabaseDir);
    BindNativeProperty(env, object, "preferencesDir", JsBaseContext::GetPreferencesDir);
    BindNativeProperty(env, object, "bundleCodeDir", JsBaseContext::GetBundleCodeDir);
    BindNativeProperty(env, object, "cloudFileDir", JsBaseContext::GetCloudFileDir);
    BindNativeProperty(env, object, "area", JsBaseContext::GetArea);
    const char *moduleName = "JsBaseContext";
    BindNativeFunction(env, object, "createBundleContext", moduleName, JsBaseContext::CreateBundleContext);
    BindNativeFunction(env, object, "getApplicationContext", moduleName, JsBaseContext::GetApplicationContext);
    BindNativeFunction(env, object, "switchArea", moduleName, JsBaseContext::SwitchArea);
    BindNativeFunction(env, object, "getArea", moduleName, JsBaseContext::GetArea);
    BindNativeFunction(env, object, "createModuleContext", moduleName, JsBaseContext::CreateModuleContext);
    BindNativeFunction(env, object, "createModuleResourceManager", moduleName,
        JsBaseContext::CreateModuleResourceManager);

    return object;
}

napi_value AttachBaseContext(napi_env env, void *value, void *hint)
{
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "called");
    if (value == nullptr || env == nullptr) {
        TAG_LOGW(AAFwkTag::ABILITY_SIM, "invalid parameter");
        return nullptr;
    }
    auto ptr = reinterpret_cast<std::weak_ptr<Context> *>(value)->lock();
    if (ptr == nullptr) {
        TAG_LOGW(AAFwkTag::ABILITY_SIM, "null ptr");
        return nullptr;
    }
    napi_value object = CreateJsBaseContext(env, ptr, true);
    auto systemModule = JsRuntime::LoadSystemModuleByEngine(env, "application.Context", &object, 1);
    if (systemModule == nullptr) {
        TAG_LOGW(AAFwkTag::ABILITY_SIM, "null systemModule");
        return nullptr;
    }

    napi_value contextObj = systemModule->GetNapiValue();
    if (!CheckTypeForNapiValue(env, contextObj, napi_object)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "get object failed");
        return nullptr;
    }
    auto workContext = new (std::nothrow) std::weak_ptr<Context>(ptr);
    napi_coerce_to_native_binding_object(
        env, contextObj, DetachNewBaseContext, AttachBaseContext, workContext, nullptr);
    napi_add_detached_finalizer(env, contextObj, DetachFinalizeBaseContext, nullptr);
    auto res = napi_wrap(env, contextObj, workContext,
        [](napi_env, void *data, void *) {
            TAG_LOGD(AAFwkTag::ABILITY_SIM, "Finalizer for weak_ptr base context is called");
            delete static_cast<std::weak_ptr<Context> *>(data);
        },
        nullptr, nullptr);
    if (res != napi_ok && workContext != nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "napi_wrap failed:%{public}d", res);
        delete workContext;
        return nullptr;
    }
    return contextObj;
}
} // namespace AbilityRuntime
} // namespace OHOS
