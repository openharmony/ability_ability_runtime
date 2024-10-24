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

#ifndef OHOS_ABILITY_RUNTIME_CJ_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_CJ_CONTEXT_H

#include <memory>

#include "cj_macro.h"
#include "cj_ability_stage_context.h"
#include "cj_application_context.h"
#include "cj_boundle_manager_utils.h"
#include "ability_runtime/cj_ability_context.h"

namespace OHOS {
namespace FfiContext {
using namespace OHOS::AbilityRuntime;

class CJContext : public FFI::FFIData {
public:
    explicit CJContext(std::weak_ptr<AbilityRuntime::Context> &&context)
        : context_(std::move(context)) {};
    std::shared_ptr<AbilityRuntime::Context> GetContext()
    {
        return context_.lock();
    }
private:
    std::weak_ptr<AbilityRuntime::Context> context_;
};

extern "C" {
CJ_EXPORT void* FfiContextGetContext(int64_t id, int32_t type);
CJ_EXPORT RetApplicationInfo FfiContextGetApplicationInfo(int64_t id, int32_t type);
CJ_EXPORT char* FfiContextGetFilesDir(int64_t id, int32_t type);
CJ_EXPORT char* FfiContextGetCacheDir(int64_t id, int32_t type);
CJ_EXPORT char* FfiContextGetTempDir(int64_t id, int32_t type);
CJ_EXPORT char* FfiContextGetResourceDir(int64_t id, int32_t type);
CJ_EXPORT char* FfiContextGetDatabaseDir(int64_t id, int32_t type);
CJ_EXPORT char* FfiContextGetPreferencesDir(int64_t id, int32_t type);
CJ_EXPORT char* FfiContextGetBundleCodeDir(int64_t id, int32_t type);
CJ_EXPORT char* FfiContextGetDistributedFilesDir(int64_t id, int32_t type);
CJ_EXPORT char* FfiContextGetCloudFileDir(int64_t id, int32_t type);
CJ_EXPORT int32_t FfiContextGetArea(int64_t id, int32_t type);
CJ_EXPORT int64_t FfiContextGetApplicationContext();
CJ_EXPORT char* FfiContextGetGroupDir(int64_t id, int32_t type, char* groupId);
CJ_EXPORT int64_t FfiContextCreateModuleContext(int64_t id, int32_t type, char* moduleName);
};
}
}
#endif // OHOS_ABILITY_RUNTIME_CJ_CONTEXT_H