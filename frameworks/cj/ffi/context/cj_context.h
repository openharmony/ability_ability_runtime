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
#include "ability_runtime/cj_ability_context.h"

namespace OHOS {
namespace FfiContext {
using namespace OHOS::AbilityRuntime;

extern "C" {
CJ_EXPORT void FfiContextGetFilesDir(int64_t id, int32_t type, void(*accept)(const char*));
CJ_EXPORT void FfiContextGetCacheDir(int64_t id, int32_t type, void(*accept)(const char*));
CJ_EXPORT void FfiContextGetTempDir(int64_t id, int32_t type, void(*accept)(const char*));
CJ_EXPORT void FfiContextGetResourceDir(int64_t id, int32_t type, void(*accept)(const char*));
CJ_EXPORT void FfiContextGetDatabaseDir(int64_t id, int32_t type, void(*accept)(const char*));
CJ_EXPORT void FfiContextGetPreferencesDir(int64_t id, int32_t type, void(*accept)(const char*));
CJ_EXPORT void FfiContextGetBundleCodeDir(int64_t id, int32_t type, void(*accept)(const char*));
CJ_EXPORT void FfiContextGetDistributedFilesDir(int64_t id, int32_t type, void(*accept)(const char*));
CJ_EXPORT void FfiContextGetCloudFileDir(int64_t id, int32_t type, void(*accept)(const char*));
};
}
}
#endif // OHOS_ABILITY_RUNTIME_CJ_CONTEXT_H