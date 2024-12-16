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

#ifndef OHOS_ABILITY_RUNTIME_NAPI_CONTEXT_HELPER_H
#define OHOS_ABILITY_RUNTIME_NAPI_CONTEXT_HELPER_H
#include "napi_common.h"
#include "ability.h"
#include "feature_ability_common.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "js_runtime_utils.h"

using Ability = OHOS::AppExecFwk::Ability;
#define MODE 0771
namespace OHOS {
namespace AppExecFwk {
#ifdef SUPPORT_GRAPHICS
napi_value SetWakeUpScreenWrap(napi_env env, napi_callback_info info, SetWakeUpScreenCB *cbData);
napi_value NAPI_SetDisplayOrientationWrap(napi_env env, napi_callback_info info,
    AsyncJSCallbackInfo *asyncCallbackInfo);
napi_value NAPI_SetShowOnLockScreen(napi_env env, napi_callback_info info);
#endif
napi_value NAPI_VerifyPermissionWrap(napi_env env, napi_callback_info info, AsyncJSCallbackInfo *asyncCallbackInfo);
napi_value GetApplicationInfoWrap(napi_env env, napi_callback_info info, AppInfoCB *appInfoCB);
AppInfoCB *CreateAppInfoCBInfo(napi_env env);
napi_value NAPI_VerifySelfPermission(napi_env env, napi_callback_info info);
napi_value NAPI_RequestPermissionsFromUser(napi_env env, napi_callback_info info);
napi_value NAPI_GetFilesDir(napi_env env, napi_callback_info info);
napi_value NAPI_GetOrCreateDistributedDir(napi_env env, napi_callback_info info);
napi_value NAPI_GetCacheDir(napi_env env, napi_callback_info info);
/**
 * @brief Obtains the type of this application.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param info The callback info passed into the callback function.
 *
 * @return The return value from NAPI C++ to JS for the module.
 */
napi_value NAPI_GetCtxAppType(napi_env env, napi_callback_info info);

/**
 * @brief Obtains the HapModuleInfo object of the application.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param info The callback info passed into the callback function.
 *
 * @return The return value from NAPI C++ to JS for the module.
 */
napi_value NAPI_GetCtxHapModuleInfo(napi_env env, napi_callback_info info);

napi_value NAPI_GetAppVersionInfo(napi_env env, napi_callback_info info);

napi_value NAPI_GetApplicationContext(napi_env env, napi_callback_info info);

/**
 * @brief Obtains information about the current ability.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param info The callback info passed into the callback function.
 *
 * @return The return value from NAPI C++ to JS for the module.
 */
napi_value NAPI_GetCtxAbilityInfo(napi_env env, napi_callback_info info);

napi_value NAPI_VerifyPermission(napi_env env, napi_callback_info info);

void GetBundleNameExecuteCallback(napi_env env, void *data);

napi_value NAPI_GetBundleNameWrap(napi_env env, napi_callback_info info, AsyncJSCallbackInfo *asyncCallbackInfo);
napi_value GetProcessInfoWrap(napi_env env, napi_callback_info info, ProcessInfoCB *processInfoCB);
ProcessInfoCB *CreateProcessInfoCBInfo(napi_env env);
ElementNameCB *CreateElementNameCBInfo(napi_env env);
napi_value GetElementNameWrap(napi_env env, napi_callback_info info, ElementNameCB *elementNameCB);
ProcessNameCB *CreateProcessNameCBInfo(napi_env env);
napi_value GetProcessNameWrap(napi_env env, napi_callback_info info, ProcessNameCB *processNameCB);

DatabaseDirCB *CreateGetDatabaseDirCBInfo(napi_env env);
napi_value GetDatabaseDirWrap(napi_env env, napi_callback_info info, DatabaseDirCB *getDatabaseDirCB);

PreferencesDirCB *CreateGetPreferencesDirCBInfo(napi_env env);
napi_value GetPreferencesDirWrap(napi_env env, napi_callback_info info, PreferencesDirCB *getPreferencesDirCB);
}  // namespace AppExecFwk
}  // namespace OHOS
#endif /* OHOS_ABILITY_RUNTIME_NAPI_CONTEXT_HELPER_H */