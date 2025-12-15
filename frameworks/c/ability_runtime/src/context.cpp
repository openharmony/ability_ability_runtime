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

#include "ability_runtime/context.h"

#include "native_extension/context_impl.h"
#include "hilog_tag_wrapper.h"

#ifdef __cplusplus
extern "C" {
#endif

AbilityRuntime_ErrorCode OH_AbilityRuntime_Context_GetCacheDir(
    AbilityRuntime_ContextHandle context, char* buffer, int32_t bufferSize, int32_t* writeLength)
{
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_Context_GetTempDir(
    AbilityRuntime_ContextHandle context, char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_Context_GetFilesDir(
    AbilityRuntime_ContextHandle context, char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_Context_GetDatabaseDir(
    AbilityRuntime_ContextHandle context, char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_Context_GetPreferencesDir(
    AbilityRuntime_ContextHandle context, char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_Context_GetBundleCodeDir(
    AbilityRuntime_ContextHandle context, char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_Context_GetDistributedFilesDir(
    AbilityRuntime_ContextHandle context, char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_Context_GetResourceDir(AbilityRuntime_ContextHandle context,
    char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_Context_GetCloudFileDir(
    AbilityRuntime_ContextHandle context, char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_Context_GetAreaMode(
    AbilityRuntime_ContextHandle context, AbilityRuntime_AreaMode* areaMode)
{
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_Context_SetAreaMode(
    AbilityRuntime_ContextHandle context, AbilityRuntime_AreaMode* areaMode)
{
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_Context_GetLogFileDir(
    AbilityRuntime_ContextHandle context, char* buffer, const int32_t bufferSize, int32_t* writeLength)
{
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

AbilityRuntime_ErrorCode OH_AbilityRuntime_Context_GetProcessName(
    AbilityRuntime_ContextHandle context, char* buffer, int32_t bufferSize, int32_t* writeLength)
{
    return ABILITY_RUNTIME_ERROR_CODE_NO_ERROR;
}

#ifdef __cplusplus
} // extern "C"
#endif