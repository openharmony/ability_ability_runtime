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

#include "sts_uri_perm_mgr.h"

#include "ability_business_error.h"
#include "ability_manager_errors.h"
#include "ability_runtime_error_util.h"
#include "hilog_tag_wrapper.h"
#include "ipc_skeleton.h"
#include "js_error_utils.h"
#include "js_runtime_utils.h"
#include "napi_common_util.h"
#include "parameters.h"
#include "tokenid_kit.h"
#include "uri.h"
#include "uri_permission_manager_client.h"
#include "sts_runtime.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
}

static std::string GetStdString(ani_env* env, ani_string str)
{
    std::string result;
    ani_size sz {};
    env->String_GetUTF8Size(str, &sz);
    result.resize(sz + 1);
    env->String_GetUTF8SubString(str, 0, sz, result.data(), result.size(), &sz);
    result.resize(sz);
    return result;
}

static ani_int grantUriPermissionPromiseSync([[maybe_unused]]ani_env *env,
    [[maybe_unused]]ani_object obj, ani_string uri, ani_int flag, ani_string targetName)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "grantUriPermissionPromiseSync run");
    std::string uriStr = GetStdString(env, uri);
    Uri uriVec(uriStr);
    int32_t flagId = static_cast<int32_t>(flag);
    std::string targetBundleName = GetStdString(env, targetName);
    return AAFwk::UriPermissionManagerClient::GetInstance().GrantUriPermission(uriVec, flagId, targetBundleName, 0);
}

static void grantUriPermissionPromiseWithAppCloneIndexSync([[maybe_unused]]ani_env *env,
    [[maybe_unused]]ani_object obj, ani_string uri, ani_int flag, ani_string targetName, ani_int appCloneIndex)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "grantUriPermissionPromiseWithAppCloneIndexSync run");
    std::string uriStr = GetStdString(env, uri);
    Uri uriVec(uriStr);
    int32_t flagId = static_cast<int32_t>(flag);
    std::string targetBundleName = GetStdString(env, targetName);
    int32_t appCloneIndexId = static_cast<int32_t>(appCloneIndex);
    AAFwk::UriPermissionManagerClient::GetInstance().GrantUriPermission(uriVec, flagId, targetBundleName, appCloneIndexId);
}

static void grantUriPermissionCallbackSync([[maybe_unused]]ani_env *env,
    [[maybe_unused]]ani_object obj, ani_string uri, ani_int flag, ani_string targetName)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "grantUriPermissionCallbackSync run");
    std::string uriStr = GetStdString(env, uri);
    Uri uriVec(uriStr);
    int32_t flagId = static_cast<int32_t>(flag);
    std::string targetBundleName = GetStdString(env, targetName);
    AAFwk::UriPermissionManagerClient::GetInstance().GrantUriPermission(uriVec, flagId, targetBundleName, 0);
}

static ani_int revokeUriPermissionPromiseSync([[maybe_unused]]ani_env *env,
    [[maybe_unused]]ani_object obj, ani_string uri, ani_string targetName)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "revokeUriPermissionPromiseSync run");
    std::string uriStr = GetStdString(env, uri);
    Uri uriVec(uriStr);
    std::string targetBundleName = GetStdString(env, targetName);
    return AAFwk::UriPermissionManagerClient::GetInstance().RevokeUriPermissionManually(uriVec,
        targetBundleName, 0);
}

static void revokeUriPermissionPromiseWithAppCloneIndexSync([[maybe_unused]]ani_env *env,
    [[maybe_unused]]ani_object obj, ani_string uri, ani_string targetName, ani_int appCloneIndex)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "revokeUriPermissionPromiseWithAppCloneIndexSync run");
    std::string uriStr = GetStdString(env, uri);
    Uri uriVec(uriStr);
    std::string targetBundleName = GetStdString(env, targetName);
    int32_t appCloneIndexId = static_cast<int32_t>(appCloneIndex);
    AAFwk::UriPermissionManagerClient::GetInstance().RevokeUriPermissionManually(uriVec,
        targetBundleName, appCloneIndexId);
}

static void revokeUriPermissionCallbackSync([[maybe_unused]]ani_env *env,
    [[maybe_unused]]ani_object obj, ani_string uri, ani_string targetName)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "revokeUriPermissionCallbackSync run");
    std::string uriStr = GetStdString(env, uri);
    Uri uriVec(uriStr);
    std::string targetBundleName = GetStdString(env, targetName);
    AAFwk::UriPermissionManagerClient::GetInstance().RevokeUriPermissionManually(uriVec,
        targetBundleName, 0);
}

void CreateJsUriPermMgr(ani_env *env)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "[zhz] CreateJsUriPermMgr call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Invalid param");
    }

    ani_namespace ns;
    if (env->FindNamespace("Lsts_uri_perm_mgr/uriPermissionManager;", &ns) != ANI_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "[zhz] FindNamespace failed");
    }
    std::array functions = {
        ani_native_function {"grantUriPermissionPromiseSync", "Lstd/core/String;ILstd/core/String;:I",
            reinterpret_cast<ani_int *>(grantUriPermissionPromiseSync)},
        ani_native_function {"grantUriPermissionPromiseWithAppCloneIndexSync", "Lstd/core/String;ILstd/core/String;I:V",
            reinterpret_cast<ani_int *>(grantUriPermissionPromiseWithAppCloneIndexSync)},
        ani_native_function {"grantUriPermissionCallbackSync", "Lstd/core/String;ILstd/core/String;:V",
            reinterpret_cast<ani_int *>(grantUriPermissionCallbackSync)},
        ani_native_function {"revokeUriPermissionPromiseSync", "Lstd/core/String;Lstd/core/String;:I",
            reinterpret_cast<ani_int *>(revokeUriPermissionPromiseSync)},
        ani_native_function {"revokeUriPermissionPromiseWithAppCloneIndexSync", "Lstd/core/String;Lstd/core/String;I:V",
            reinterpret_cast<ani_int *>(revokeUriPermissionPromiseWithAppCloneIndexSync)},
        ani_native_function {"revokeUriPermissionCallbackSync", "Lstd/core/String;Lstd/core/String;:V",
            reinterpret_cast<ani_int *>(revokeUriPermissionCallbackSync)},
    };
    TAG_LOGI(AAFwkTag::URIPERMMGR, "[zhz] CreateJsUriPermMgr bind functions");
    if (env->Namespace_BindNativeFunctions(ns, functions.data(), functions.size()) != ANI_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "[zhz] Namespace_BindNativeFunctions failed");
    };
    TAG_LOGI(AAFwkTag::URIPERMMGR, "[zhz] CreateJsUriPermMgr success");
}
}  // namespace AbilityRuntime
}  // namespace OHOS
