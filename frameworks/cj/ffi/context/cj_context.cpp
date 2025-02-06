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
 
#include "cj_context.h"

#include "context.h"
#include "cj_utils_ffi.h"
#include "cj_macro.h"
#include "cj_application_context.h"
#include "cj_ability_runtime_error.h"
#include "bundle_manager_convert.h"
#include "hilog_tag_wrapper.h"
#include "js_context_utils.h"

namespace OHOS {
namespace FfiContext {
using namespace OHOS::FFI;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::CJSystemapi::BundleManager;

std::shared_ptr<AbilityRuntime::Context> GetContextFromCJ(int64_t id)
{
    auto cjContext = FFI::FFIData::GetData<CJContext>(id);
    if (cjContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null cjContext");
        return nullptr;
    }
    return cjContext->GetContext();
}

extern "C" {
CJ_EXPORT void* FfiContextGetContext(int64_t id, int32_t type)
{
    (void)type;
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    // return shared_ptr.get() is not safe!
    return nativeContext.get();
}

CJ_EXPORT RetApplicationInfo FfiContextGetApplicationInfo(int64_t id, int32_t type)
{
    (void)type;
    RetApplicationInfo appInfo;
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return appInfo;
    }
    auto applicationInfo = nativeContext->GetApplicationInfo();
    if (applicationInfo == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null applicationInfo");
        return appInfo;
    }
    return Convert::ConvertApplicationInfo(*applicationInfo);
}

CJ_EXPORT char* FfiContextGetFilesDir(int64_t id, int32_t type)
{
    (void)type;
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    auto filesDir = nativeContext->GetFilesDir();
    return CreateCStringFromString(filesDir);
}

CJ_EXPORT char* FfiContextGetCacheDir(int64_t id, int32_t type)
{
    (void)type;
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    auto cacheDir = nativeContext->GetCacheDir();
    return CreateCStringFromString(cacheDir);
}

CJ_EXPORT char* FfiContextGetTempDir(int64_t id, int32_t type)
{
    (void)type;
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    auto tempDir = nativeContext->GetTempDir();
    return CreateCStringFromString(tempDir);
}

CJ_EXPORT char* FfiContextGetResourceDir(int64_t id, int32_t type)
{
    (void)type;
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    auto resourceDir = nativeContext->GetResourceDir();
    return CreateCStringFromString(resourceDir);
}

CJ_EXPORT char* FfiContextGetDatabaseDir(int64_t id, int32_t type)
{
    (void)type;
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    auto databaseDir = nativeContext->GetDatabaseDir();
    return CreateCStringFromString(databaseDir);
}

CJ_EXPORT char* FfiContextGetPreferencesDir(int64_t id, int32_t type)
{
    (void)type;
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    auto preferencesDir = nativeContext->GetPreferencesDir();
    return CreateCStringFromString(preferencesDir);
}

CJ_EXPORT char* FfiContextGetBundleCodeDir(int64_t id, int32_t type)
{
    (void)type;
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    auto bundleCodeDir = nativeContext->GetBundleCodeDir();
    return CreateCStringFromString(bundleCodeDir);
}

CJ_EXPORT char* FfiContextGetDistributedFilesDir(int64_t id, int32_t type)
{
    (void)type;
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    auto distributedFilesDir = nativeContext->GetDistributedFilesDir();
    return CreateCStringFromString(distributedFilesDir);
}

CJ_EXPORT char* FfiContextGetCloudFileDir(int64_t id, int32_t type)
{
    (void)type;
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    auto cloudFileDir = nativeContext->GetCloudFileDir();
    return CreateCStringFromString(cloudFileDir);
}

CJ_EXPORT int32_t FfiContextGetArea(int64_t id, int32_t type)
{
    (void)type;
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return -1;
    }
    return nativeContext->GetArea();
}

CJ_EXPORT int64_t FfiContextGetApplicationContext()
{
    auto appContext = ApplicationContextCJ::CJApplicationContext::GetCJApplicationContext(
        AbilityRuntime::Context::GetApplicationContext());
    if (appContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null app context");
        return -1;
    }
    return appContext->GetID();
}

CJ_EXPORT char* FfiContextGetGroupDir(int64_t id, int32_t type, char* groupId)
{
    (void)type;
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    auto groupDir = nativeContext->GetGroupDir(std::string(groupId));
    return CreateCStringFromString(groupDir);
}

CJ_EXPORT int64_t FfiContextCreateModuleContext(int64_t id, int32_t type, char* moduleName)
{
    (void)type;
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return -1;
    }
    auto moduleContext = nativeContext->CreateModuleContext(std::string(moduleName));
    if (moduleContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return -ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
    }
    auto cjContext = FFIData::Create<CJContext>(moduleContext);
    if (cjContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return -1;
    }
    return cjContext->GetID();
}

CJ_EXPORT napi_value FfiConvertBaseContext2Napi(napi_env env, int64_t id)
{
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);
    auto cjContext = FFIData::GetData<CJContext>(id);
    if (cjContext == nullptr || cjContext->GetContext() == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "cj context null ptr");
        return undefined;
    }

    napi_value result = CreateJsBaseContext(env, cjContext->GetContext());
    if (result == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null object");
        return undefined;
    }
    auto workContext = new (std::nothrow) std::weak_ptr<Context>(cjContext->GetContext());
    auto res = napi_wrap(env, result, workContext,
        [](napi_env, void *data, void *) {
            TAG_LOGD(AAFwkTag::APPKIT, "Finalizer for weak_ptr base context is called");
            delete static_cast<std::weak_ptr<Context> *>(data);
        },
        nullptr, nullptr);
    if (res != napi_ok && workContext != nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "napi_wrap failed:%{public}d", res);
        delete workContext;
        return undefined;
    }
    napi_value falseValue = nullptr;
    napi_get_boolean((napi_env)env, true, &falseValue);
    napi_set_named_property((napi_env)env, result, "stageMode", falseValue);
    return result;
}

CJ_EXPORT int64_t FfiCreateBaseContextFromNapi(napi_env env, napi_value baseContext)
{
    if (env == nullptr || baseContext == nullptr) {
        return ERR_INVALID_INSTANCE_CODE;
    }

    napi_valuetype type;
    if (napi_typeof(env, baseContext, &type) || type != napi_object) {
        return ERR_INVALID_INSTANCE_CODE;
    }

    std::weak_ptr<Context>* context = nullptr;
    napi_status status = napi_unwrap(env, baseContext, reinterpret_cast<void**>(&context));
    if (status != napi_ok) {
        return ERR_INVALID_INSTANCE_CODE;
    }

    if (context == nullptr || (*context).lock() == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto cjContext = FFI::FFIData::Create<CJContext>((*context).lock());
    if (cjContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null cjContext");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return cjContext->GetID();
}
}
}
}