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
#include "hilog_tag_wrapper.h"
#include "cj_ability_runtime_error.h"

namespace OHOS {
namespace FfiContext {
using namespace OHOS::FFI;
using namespace OHOS::AbilityRuntime;

static constexpr int32_t ABILITY_CONTEXT = 0;
static constexpr int32_t APPLICATION_CONTEXT = 1;
static constexpr int32_t ABILITY_STAGE_CONTEXT = 2;

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
    }
    return nullptr;
}

void FfiContextGetFilesDir(int64_t id, int32_t type, void(*accept)(const char*))
{
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id, type);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return;
    }
    auto filesDir = nativeContext->GetFilesDir();
    accept(filesDir.c_str());
}

void FfiContextGetCacheDir(int64_t id, int32_t type, void(*accept)(const char*))
{
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id, type);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return;
    }
    auto cacheDir = nativeContext->GetCacheDir();
    accept(cacheDir.c_str());
}

void FfiContextGetTempDir(int64_t id, int32_t type, void(*accept)(const char*))
{
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id, type);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return;
    }
    auto tempDir = nativeContext->GetTempDir();
    accept(tempDir.c_str());
}

void FfiContextGetResourceDir(int64_t id, int32_t type, void(*accept)(const char*))
{
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id, type);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return;
    }
    auto resourceDir = nativeContext->GetResourceDir();
    accept(resourceDir.c_str());
}

void FfiContextGetDatabaseDir(int64_t id, int32_t type, void(*accept)(const char*))
{
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id, type);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return;
    }
    auto databaseDir = nativeContext->GetDatabaseDir();
    accept(databaseDir.c_str());
}

void FfiContextGetPreferencesDir(int64_t id, int32_t type, void(*accept)(const char*))
{
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id, type);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return;
    }
    auto preferencesDir = nativeContext->GetPreferencesDir();
    accept(preferencesDir.c_str());
}

void FfiContextGetBundleCodeDir(int64_t id, int32_t type, void(*accept)(const char*))
{
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id, type);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return;
    }
    auto bundleCodeDir = nativeContext->GetBundleCodeDir();
    accept(bundleCodeDir.c_str());
}

void FfiContextGetDistributedFilesDir(int64_t id, int32_t type, void(*accept)(const char*))
{
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id, type);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return;
    }
    auto distributedFilesDir = nativeContext->GetDistributedFilesDir();
    accept(distributedFilesDir.c_str());
}

void FfiContextGetCloudFileDir(int64_t id, int32_t type, void(*accept)(const char*))
{
    std::shared_ptr<AbilityRuntime::Context> nativeContext = GetContextFromCJ(id, type);
    if (nativeContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return;
    }
    auto cloudFileDir = nativeContext->GetCloudFileDir();
    accept(cloudFileDir.c_str());
}

}
}