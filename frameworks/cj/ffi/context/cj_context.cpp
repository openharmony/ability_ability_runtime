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

#include "cj_utils_ffi.h"
#include "cj_ability_runtime_error.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace FfiContext {
using namespace OHOS::FFI;
using namespace OHOS::AbilityRuntime;

static constexpr int32_t ABILITY_CONTEXT = 0;
static constexpr int32_t APPLICATION_CONTEXT = 1;
static constexpr int32_t ABILITY_STAGE_CONTEXT = 2;
static constexpr int32_t CJ_CONTEXT = 3;

std::shared_ptr<AbilityRuntime::Context> GetCJContextFromCJ(int64_t id)
{
    auto cjContext = FFI::FFIData::GetData<CJContext>(id);
    if (cjContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null cj AbilityContext");
        return nullptr;
    }
    auto context = cjContext->GetContext();
    return context;
}

std::shared_ptr<AbilityRuntime::Context> GetAbilityContextFromCJ(int64_t id)
{
    auto cjAbilityContext = FFI::FFIData::GetData<CJAbilityContext>(id);
    if (cjAbilityContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null cj AbilityContext");
        return nullptr;
    }
    auto abilityContext = cjAbilityContext->GetAbilityContext();
    return abilityContext;
}

std::shared_ptr<AbilityRuntime::Context> GetApplicationContextFromCJ(int64_t id)
{
    auto cjAppContext = FFI::FFIData::GetData<ApplicationContextCJ::CJApplicationContext>(id);
    if (cjAppContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null cj ApplicationContext");
        return nullptr;
    }
    auto appContext = cjAppContext->GetApplicationContext();
    return appContext;
}

std::shared_ptr<AbilityRuntime::Context> GetAbilityStageContextFromCJ(int64_t id)
{
    auto cjAbilityStageContext = FFI::FFIData::GetData<CJAbilityStageContext>(id);
    if (cjAbilityStageContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null cj AbilityContext");
        return nullptr;
    }
    auto abilityStageContext = cjAbilityStageContext->GetContext();
    return abilityStageContext;
}

std::shared_ptr<AbilityRuntime::Context> GetContextFromCJ(int64_t id, int32_t type)
{
    if (type == ABILITY_CONTEXT) {
        return GetAbilityContextFromCJ(id);
    } else if (type == APPLICATION_CONTEXT) {
        return GetApplicationContextFromCJ(id);
    } else if (type == ABILITY_STAGE_CONTEXT) {
        return GetAbilityStageContextFromCJ(id);
    } else if (type == CJ_CONTEXT) {
        return GetCJContextFromCJ(id);
    }
    return nullptr;
}

void* FfiContextGetContext(int64_t id, int32_t type)
{
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id, type);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    return nativeContext.get();
}

RetApplicationInfo FfiContextGetApplicationInfo(int64_t id, int32_t type)
{
    RetApplicationInfo appInfo;
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id, type);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return appInfo;
    }
    auto applicationInfo = nativeContext->GetApplicationInfo();
    if (applicationInfo == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null applicationInfo");
        return appInfo;
    }
    return ConvertApplicationInfo(*applicationInfo);
}

char* FfiContextGetFilesDir(int64_t id, int32_t type)
{
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id, type);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    auto filesDir = nativeContext->GetFilesDir();
    return CreateCStringFromString(filesDir);
}

char* FfiContextGetCacheDir(int64_t id, int32_t type)
{
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id, type);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    auto cacheDir = nativeContext->GetCacheDir();
    return CreateCStringFromString(cacheDir);
}

char* FfiContextGetTempDir(int64_t id, int32_t type)
{
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id, type);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    auto tempDir = nativeContext->GetTempDir();
    return CreateCStringFromString(tempDir);
}

char* FfiContextGetResourceDir(int64_t id, int32_t type)
{
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id, type);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    auto resourceDir = nativeContext->GetResourceDir();
    return CreateCStringFromString(resourceDir);
}

char* FfiContextGetDatabaseDir(int64_t id, int32_t type)
{
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id, type);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    auto databaseDir = nativeContext->GetDatabaseDir();
    return CreateCStringFromString(databaseDir);
}

char* FfiContextGetPreferencesDir(int64_t id, int32_t type)
{
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id, type);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    auto preferencesDir = nativeContext->GetPreferencesDir();
    return CreateCStringFromString(preferencesDir);
}

char* FfiContextGetBundleCodeDir(int64_t id, int32_t type)
{
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id, type);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    auto bundleCodeDir = nativeContext->GetBundleCodeDir();
    return CreateCStringFromString(bundleCodeDir);
}

char* FfiContextGetDistributedFilesDir(int64_t id, int32_t type)
{
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id, type);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    auto distributedFilesDir = nativeContext->GetDistributedFilesDir();
    return CreateCStringFromString(distributedFilesDir);
}

char* FfiContextGetCloudFileDir(int64_t id, int32_t type)
{
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id, type);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    auto cloudFileDir = nativeContext->GetCloudFileDir();
    return CreateCStringFromString(cloudFileDir);
}

int32_t FfiContextGetArea(int64_t id, int32_t type)
{
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id, type);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return -1;
    }
    return nativeContext->GetArea();
}

int64_t FfiContextGetApplicationContext()
{
    auto appContext = ApplicationContextCJ::CJApplicationContext::GetCJApplicationContext(
        AbilityRuntime::Context::GetApplicationContext());
    if (appContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null app context");
        return -1;
    }
    return appContext->GetID();
}

char* FfiContextGetGroupDir(int64_t id, int32_t type, char* groupId)
{
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id, type);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return nullptr;
    }
    auto groupDir = nativeContext->GetGroupDir(std::string(groupId));
    return CreateCStringFromString(groupDir);
}

int64_t FfiContextCreateModuleContext(int64_t id, int32_t type, char* moduleName)
{
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id, type);
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