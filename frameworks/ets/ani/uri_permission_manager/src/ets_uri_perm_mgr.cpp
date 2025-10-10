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

#include "ets_uri_perm_mgr.h"

#include "ability_business_error.h"
#include "ability_manager_errors.h"
#include "ability_runtime_error_util.h"
#include "ani_common_util.h"
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
#include "ets_error_utils.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char* WRAPPER_CLASS_NAME = "Lutils/AbilityUtils/AsyncCallbackWrapper;";
constexpr const char* ERROR_CLASS_NAME = "Lescompat/Error;";
constexpr const char* BUSINESS_ERROR_CLASS_NAME = "L@ohos/base/BusinessError;";
constexpr const char *INVOKE_METHOD_NAME = "invoke";
constexpr const int32_t ERR_OK = 0;
constexpr const int32_t ERR_FAILURE = -1;
constexpr const char* NOT_SYSTEM_APP = "The application is not system-app, can not use system-api.";

ani_object CreateDouble(ani_env *env, int32_t res)
{
    if (env == nullptr) {
        return nullptr;
    }
    static const char *className = "Lstd/core/Double;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "create double error");
        return nullptr;
    }

    if (cls == nullptr) {
        return nullptr;
    }
    ani_method ctor;
    env->Class_FindMethod(cls, "<ctor>", "D:V", &ctor);
    if (ctor == nullptr) {
        return nullptr;
    }
    ani_object obj;
    env->Object_New(cls, ctor, &obj, ani_double(res));
    return obj;
}

}

static std::string GetStdString(ani_env* env, ani_string str)
{
    if (env == nullptr) {
        return std::string();
    }
    std::string result;
    ani_size sz {};
    env->String_GetUTF8Size(str, &sz);
    result.resize(sz + 1);
    env->String_GetUTF8SubString(str, 0, sz, result.data(), result.size(), &sz);
    result.resize(sz);
    return result;
}

static void grantUriPermissionCallbackSync([[maybe_unused]]ani_env *env,
    ani_string uri, ani_enum_item flagEnum, ani_string targetName, ani_int appCloneIndex, ani_object callback)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "grantUriPermissionCallbackSync run");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "env null");
        return;
    }
    auto selfToken = IPCSkeleton::GetSelfTokenID();
    ani_object etsErrCode = EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK);
    if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "app not system-app");
        etsErrCode = EtsErrorUtil::CreateError(env,
            static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_NOT_SYSTEM_APP), NOT_SYSTEM_APP);
        AsyncCallback(env, callback, etsErrCode, CreateDouble(env, ERR_FAILURE));
        return;
    }
    std::string uriStr = GetStdString(env, uri);
    Uri uriVec(uriStr);
    ani_int flag = 0;
    AAFwk::AniEnumConvertUtil::EnumConvert_EtsToNative(env, flagEnum, flag);
    int32_t flagId = static_cast<int32_t>(flag);
    std::string targetBundleName = GetStdString(env, targetName);
    int32_t result = ERR_OK;
    int32_t errCode = AAFwk::UriPermissionManagerClient::GetInstance().GrantUriPermission(uriVec, flagId,
        targetBundleName, appCloneIndex);
    if (errCode != ERR_OK) {
        result = ERR_FAILURE;
        etsErrCode = EtsErrorUtil::CreateErrorByNativeErr(env, errCode);
    }
    
    AsyncCallback(env, callback, etsErrCode, CreateDouble(env, result));
}

static void revokeUriPermissionCallbackSync([[maybe_unused]]ani_env *env,
    ani_string uri, ani_string targetName, ani_int appCloneIndex, ani_object callback)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "revokeUriPermissionCallbackSync run");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "env null");
        return;
    }
    auto selfToken = IPCSkeleton::GetSelfTokenID();
    ani_object etsErrCode = EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK);
    if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "app not system-app");
        etsErrCode = EtsErrorUtil::CreateError(env,
            static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_NOT_SYSTEM_APP), NOT_SYSTEM_APP);
        AsyncCallback(env, callback, etsErrCode, CreateDouble(env, ERR_FAILURE));
        return;
    }
    std::string uriStr = GetStdString(env, uri);
    Uri uriVec(uriStr);
    std::string targetBundleName = GetStdString(env, targetName);
    int32_t result = ERR_OK;
    int32_t errCode = AAFwk::UriPermissionManagerClient::GetInstance().RevokeUriPermissionManually(uriVec,
        targetBundleName, appCloneIndex);
    if (errCode != ERR_OK) {
        result = ERR_FAILURE;
        etsErrCode = EtsErrorUtil::CreateErrorByNativeErr(env, errCode);
    }
    AsyncCallback(env, callback, etsErrCode, CreateDouble(env, result));
}

static void grantUriPermissionByKeyCallbackSync([[maybe_unused]]ani_env *env,
    ani_string uri, ani_enum_item flagEnum, ani_int targetTokenId, ani_object callback)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "grantUriPermissionByKeyCallbackSync start");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "env null");
        return;
    }
    auto selfToken = IPCSkeleton::GetSelfTokenID();
    ani_object etsErrCode = EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK);
    if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "app not system-app");
        etsErrCode = EtsErrorUtil::CreateError(env,
            static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_NOT_SYSTEM_APP), NOT_SYSTEM_APP);
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_NOT_SYSTEM_APP);
        return;
    }
    std::string uriStr = GetStdString(env, uri);
    ani_int flag = 0;
    AAFwk::AniEnumConvertUtil::EnumConvert_EtsToNative(env, flagEnum, flag);
    int32_t result = ERR_OK;
    int32_t errCode =
        AAFwk::UriPermissionManagerClient::GetInstance().GrantUriPermissionByKey(uriStr, flag, targetTokenId);
    if (errCode != ERR_OK) {
        result = ERR_FAILURE;
        TAG_LOGE(AAFwkTag::DELEGATOR, "GrantUriPermissionByKey failed status: %{public}d", errCode);
        etsErrCode = EtsErrorUtil::CreateErrorByNativeErr(env, errCode);
        AsyncCallback(env, callback, etsErrCode, CreateDouble(env, result));
        return;
    }
    etsErrCode = EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK);
    AppExecFwk::AsyncCallback(env, callback, etsErrCode, nullptr);
}

static void grantUriPermissionByKeyAsCallerCallbackSync([[maybe_unused]]ani_env *env,
    ani_string uri, ani_enum_item flagEnum, ani_int callerTokenId, ani_int targetTokenId, ani_object callback)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "grantUriPermissionByKeyAsCallerCallbackSync start");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "env null");
        return;
    }
    auto selfToken = IPCSkeleton::GetSelfTokenID();
    ani_object etsErrCode = EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK);
    if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "app not system-app");
        etsErrCode = EtsErrorUtil::CreateError(env,
            static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_NOT_SYSTEM_APP), NOT_SYSTEM_APP);
        AsyncCallback(env, callback, etsErrCode, CreateDouble(env, ERR_FAILURE));
        return;
    }
    std::string uriStr = GetStdString(env, uri);
    ani_int flag = 0;
    AAFwk::AniEnumConvertUtil::EnumConvert_EtsToNative(env, flagEnum, flag);
    int32_t result = ERR_OK;
    int32_t errCode = AAFwk::UriPermissionManagerClient::GetInstance().GrantUriPermissionByKeyAsCaller(
        uriStr, flag, callerTokenId, targetTokenId);
    if (errCode != ERR_OK) {
        result = ERR_FAILURE;
        etsErrCode = EtsErrorUtil::CreateErrorByNativeErr(env, errCode);
    }
    AppExecFwk::AsyncCallback(env, callback, etsErrCode, CreateDouble(env, result));
}

void EtsUriPermissionManagerInit(ani_env *env)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "EtsUriPermissionManagerInit call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Invalid param");
        return;
    }
    ani_namespace ns;
    const char* targetNamespace = "L@ohos/application/uriPermissionManager/uriPermissionManager;";
    if (env->FindNamespace(targetNamespace, &ns) != ANI_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "FindNamespace failed");
    }
    if (ns == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "ns null");
        return;
    }
    std::array functions = {
        ani_native_function {
            "grantUriPermissionCallbackSync",
            "Lstd/core/String;L@ohos/app/ability/wantConstant/wantConstant/Flags;Lstd/core/String;I"
            "Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
            reinterpret_cast<void*>(grantUriPermissionCallbackSync)
        },
        ani_native_function {
            "revokeUriPermissionCallbackSync",
            "Lstd/core/String;Lstd/core/String;I"
            "Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
            reinterpret_cast<void*>(revokeUriPermissionCallbackSync)
        },
        ani_native_function {
            "grantUriPermissionByKeyCallbackSync",
            nullptr,
            reinterpret_cast<void*>(grantUriPermissionByKeyCallbackSync)
        },
        ani_native_function {
            "grantUriPermissionByKeyAsCallerCallbackSync",
            nullptr,
            reinterpret_cast<void*>(grantUriPermissionByKeyAsCallerCallbackSync)
        }
    };
    TAG_LOGI(AAFwkTag::URIPERMMGR, "EtsUriPermissionManagerInit bind functions");
    if (env->Namespace_BindNativeFunctions(ns, functions.data(), functions.size()) != ANI_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Namespace_BindNativeFunctions failed");
    };
    TAG_LOGI(AAFwkTag::URIPERMMGR, "EtsUriPermissionManagerInit end");
}

extern "C"{
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "ANI_Constructor");
    if (vm == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "vm null");
        return ANI_ERROR;
    }
    if (result == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "result null");
        return ANI_ERROR;
    }
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::URIPERMMGR, "GetEnv failed status: %{public}d", status);
        return ANI_NOT_FOUND;
    }

    EtsUriPermissionManagerInit(env);
    *result = ANI_VERSION_1;
    TAG_LOGI(AAFwkTag::URIPERMMGR, "ANI_Constructor finish");
    return ANI_OK;
}
}

bool AsyncCallback(ani_env *env, ani_object call, ani_object error, ani_object result)
{
    ani_status status = ANI_ERROR;
    ani_class clsCall {};

    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "env null");
        return false;
    }

    if ((status = env->FindClass(WRAPPER_CLASS_NAME, &clsCall)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "status: %{public}d", status);
        return false;
    }
    ani_method method = {};
    if ((status = env->Class_FindMethod(
        clsCall, INVOKE_METHOD_NAME, "L@ohos/base/BusinessError;Lstd/core/Object;:V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "status: %{public}d", status);
        return false;
    }
    if (method == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "method null");
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

ani_object WrapError(ani_env *env, const std::string &msg)
{
    ani_class cls {};
    ani_method method {};
    ani_object obj = nullptr;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "null env");
        return nullptr;
    }
    ani_string aniMsg = GetAniString(env, msg);
    ani_ref undefRef;
    env->GetUndefined(&undefRef);
    if ((status = env->FindClass(ERROR_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "statys: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", "Lstd/core/String;Lescompat/ErrorOptions;:V", &method)) !=
        ANI_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &obj, aniMsg, undefRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "status: %{public}d", status);
        return nullptr;
    }
    return obj;
}

ani_string GetAniString(ani_env *env, const std::string &str)
{
    ani_string aniStr = nullptr;
    ani_status status = env->String_NewUTF8(str.c_str(), str.size(), &aniStr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return nullptr;
    }
    return aniStr;
}

ani_object WrapBusinessError(ani_env *env, int32_t code)
{
    ani_class cls {};
    ani_method method {};
    ani_object obj = nullptr;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return nullptr;
    }
    if ((status = env->FindClass(BUSINESS_ERROR_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", "DLescompat/Error;:V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    ani_object error = WrapError(env, GetErrMsg(code));
    if (error == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "error nulll");
        return nullptr;
    }
    ani_double dCode(code);
    if ((status = env->Object_New(cls, method, &obj, dCode, error)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    return obj;
}

std::string GetErrMsg(int32_t err, const std::string &permission)
{
    auto errCode = GetJsErrorCodeByNativeError(err);
    auto errMsg = (errCode == AbilityErrorCode::ERROR_CODE_PERMISSION_DENIED && !permission.empty())
                      ? GetNoPermissionErrorMsg(permission)
                      : GetErrorMsg(errCode);
    return errMsg;
}

} // namespace AbilityRuntime
} // namespace OHOS