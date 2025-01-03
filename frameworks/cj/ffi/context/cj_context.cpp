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
}
}
}