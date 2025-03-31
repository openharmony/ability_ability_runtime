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
#include "ani_enum_convert.h"
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
const char *INVOKE_METHOD_NAME = "invoke";
const int32_t ERR_OK = 0;
const int32_t ERR_FAILURE = -1;

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
    ani_string uri, ani_enum_item flagEnum, ani_string targetName)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "grantUriPermissionPromiseSync run");
    std::string uriStr = GetStdString(env, uri);
    Uri uriVec(uriStr);
    ani_int flag;
    AAFwk::AniEnumConvertUtil::EnumConvert_StsToNative(env, flagEnum, flag);
    int32_t flagId = static_cast<int32_t>(flag);
    std::string targetBundleName = GetStdString(env, targetName);
    return AAFwk::UriPermissionManagerClient::GetInstance().GrantUriPermission(uriVec, flagId, targetBundleName, 0);
}

static void grantUriPermissionPromiseWithAppCloneIndexSync([[maybe_unused]]ani_env *env,
    ani_string uri, ani_enum_item flagEnum, ani_string targetName, ani_int appCloneIndex)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "grantUriPermissionPromiseWithAppCloneIndexSync run");
    std::string uriStr = GetStdString(env, uri);
    Uri uriVec(uriStr);
    ani_int flag;
    AAFwk::AniEnumConvertUtil::EnumConvert_StsToNative(env, flagEnum, flag);
    int32_t flagId = static_cast<int32_t>(flag);
    std::string targetBundleName = GetStdString(env, targetName);
    int32_t appCloneIndexId = static_cast<int32_t>(appCloneIndex);
    AAFwk::UriPermissionManagerClient::GetInstance().GrantUriPermission(uriVec, flagId, targetBundleName, appCloneIndexId);
}

static void grantUriPermissionCallbackSync([[maybe_unused]]ani_env *env,
    ani_string uri, ani_enum_item flagEnum, ani_string targetName, ani_object callback)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "grantUriPermissionCallbackSync run");
    std::string uriStr = GetStdString(env, uri);
    Uri uriVec(uriStr);
    ani_int flag;
    AAFwk::AniEnumConvertUtil::EnumConvert_StsToNative(env, flagEnum, flag);
    int32_t flagId = static_cast<int32_t>(flag);
    std::string targetBundleName = GetStdString(env, targetName);
    int32_t ret = ERR_OK;
    ret = AAFwk::UriPermissionManagerClient::GetInstance().GrantUriPermission(uriVec, flagId, targetBundleName, 0);
    if (ret != ERR_OK) {
        ret = ERR_FAILURE;
    }
    AsyncCallback(env, callback, WrapBusinessError(env, static_cast<int32_t>(ret)), nullptr);
}

static ani_int revokeUriPermissionPromiseSync([[maybe_unused]]ani_env *env,
    ani_string uri, ani_string targetName)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "revokeUriPermissionPromiseSync run");
    std::string uriStr = GetStdString(env, uri);
    Uri uriVec(uriStr);
    std::string targetBundleName = GetStdString(env, targetName);
    return AAFwk::UriPermissionManagerClient::GetInstance().RevokeUriPermissionManually(uriVec,
        targetBundleName, 0);
}

static void revokeUriPermissionPromiseWithAppCloneIndexSync([[maybe_unused]]ani_env *env,
    ani_string uri, ani_string targetName, ani_int appCloneIndex)
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
    ani_string uri, ani_string targetName, ani_object callback)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "revokeUriPermissionCallbackSync run");
    std::string uriStr = GetStdString(env, uri);
    Uri uriVec(uriStr);
    std::string targetBundleName = GetStdString(env, targetName);
    int32_t ret = ERR_OK;
    ret = AAFwk::UriPermissionManagerClient::GetInstance().RevokeUriPermissionManually(uriVec,
        targetBundleName, 0);
    if (ret != ERR_OK) {
        ret = ERR_FAILURE;
    }
    AsyncCallback(env, callback, WrapBusinessError(env, static_cast<int32_t>(ret)), nullptr);
}

void StsUriPermissionManagerInit(ani_env *env)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "StsUriPermissionManagerInit call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Invalid param");
    }
    ani_namespace ns;
    const char* targetNamespace = "L@ohos/application/uriPermissionManager/uriPermissionManager;";
    if (env->FindNamespace(targetNamespace, &ns) != ANI_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "FindNamespace failed");
    }
    std::array functions = {
        ani_native_function {
            "grantUriPermissionPromiseSync",
            "Lstd/core/String;L@ohos/app/ability/wantConstant/wantConstant/Flags;Lstd/core/String;:I",
            reinterpret_cast<void*>(grantUriPermissionPromiseSync)
        },
        ani_native_function {
            "grantUriPermissionPromiseWithAppCloneIndexSync",
            "Lstd/core/String;L@ohos/app/ability/wantConstant/wantConstant/Flags;Lstd/core/String;I:V",
            reinterpret_cast<void*>(grantUriPermissionPromiseWithAppCloneIndexSync)
        },
        ani_native_function {
            "grantUriPermissionCallbackSync",
            "Lstd/core/String;L@ohos/app/ability/wantConstant/wantConstant/Flags;Lstd/core/String;"
            "L@ohos/application/uriPermissionManager/AsyncCallbackWrapper;:V",
            reinterpret_cast<void*>(grantUriPermissionCallbackSync)
        },
        ani_native_function {
            "revokeUriPermissionPromiseSync", "Lstd/core/String;Lstd/core/String;:I",
            reinterpret_cast<void*>(revokeUriPermissionPromiseSync)
        },
        ani_native_function {
            "revokeUriPermissionPromiseWithAppCloneIndexSync", "Lstd/core/String;Lstd/core/String;I:V",
            reinterpret_cast<void*>(revokeUriPermissionPromiseWithAppCloneIndexSync)
        },
        ani_native_function {
            "revokeUriPermissionCallbackSync",
            "Lstd/core/String;Lstd/core/String;"
            "L@ohos/application/uriPermissionManager/AsyncCallbackWrapper;:V",
            reinterpret_cast<void*>(revokeUriPermissionCallbackSync)
        },
    };
    TAG_LOGI(AAFwkTag::URIPERMMGR, "StsUriPermissionManagerInit bind functions");
    if (env->Namespace_BindNativeFunctions(ns, functions.data(), functions.size()) != ANI_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Namespace_BindNativeFunctions failed");
    };
    TAG_LOGI(AAFwkTag::URIPERMMGR, "StsUriPermissionManagerInit success");
}

extern "C"{
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "ANI_Constructor");
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::URIPERMMGR, "GetEnv failed status: %{public}d", status);
        return ANI_NOT_FOUND;
    }

    StsUriPermissionManagerInit(env);
    *result = ANI_VERSION_1;
    TAG_LOGI(AAFwkTag::URIPERMMGR, "ANI_Constructor finish");
    return ANI_OK;
}
}

bool AsyncCallback(ani_env *env, ani_object call, ani_object error, ani_object result)
{
    ani_status status = ANI_ERROR;
    ani_class clsCall = nullptr;

    if ((status = env->FindClass("Lapplication/UIAbilityContext/AsyncCallbackWrapper;", &clsCall)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "status: %{public}d", status);
        return false;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(
        clsCall, INVOKE_METHOD_NAME, "L@ohos/base/BusinessError;Lstd/core/Object;:V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "status: %{public}d", status);
        return false;
    }
    if (result == nullptr) {
        ani_ref nullRef = nullptr;
        env->GetNull(&nullRef);
        result = reinterpret_cast<ani_object>(nullRef);
    }
    if ((status = env->Object_CallMethod_Void(call, method, error, result)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "status: %{public}d", status);
        return false;
    }
    return true;
}

ani_object WrapBusinessError(ani_env *env, ani_int code)
{
    ani_class cls = nullptr;
    ani_field field = nullptr;
    ani_method method = nullptr;
    ani_object obj = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass("L@ohos/base/BusinessError;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", nullptr, &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &obj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindField(cls, "code", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_SetField_Int(obj, field, code)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "status: %{public}d", status);
        return nullptr;
    }
    return obj;
}

}  // namespace AbilityRuntime
}  // namespace OHOS
