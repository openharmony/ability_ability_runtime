/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "js_uri_perm_mgr.h"

#include "ability_business_error.h"
#include "ability_manager_errors.h"
#include "ability_runtime_error_util.h"
#include "hilog_tag_wrapper.h"
#include "ipc_skeleton.h"
#include "js_error_utils.h"
#include "napi_common_util.h"
#include "parameters.h"
#include "tokenid_kit.h"
#include "uri.h"
#include "uri_permission_manager_client.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr int32_t ERR_OK = 0;
constexpr int32_t argCountFour = 4;
constexpr int32_t argCountThree = 3;
constexpr int32_t argCountTwo = 2;

struct UriPermissionParam {
    std::string uriStr;
    int32_t flag = 0;
    std::string bundleName;
    int32_t appIndex = 0;
    bool hasAppIndex = false;
};

static void ResolveGrantUriPermissionTask(napi_env env, NapiAsyncTask &task, int32_t errCode)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "ResolveGrantUriPermissionTask");
    if (errCode == ERR_OK) {
        task.ResolveWithNoError(env, CreateJsUndefined(env));
        return;
    }
    if (errCode == AAFwk::CHECK_PERMISSION_FAILED || errCode == AAFwk::ERR_CODE_INVALID_URI_FLAG ||
        errCode == AAFwk::ERR_CODE_INVALID_URI_TYPE || errCode == AAFwk::ERR_CODE_GRANT_URI_PERMISSION) {
        task.Reject(env, CreateJsErrorByNativeErr(env, errCode, "ohos.permission.PROXY_AUTHORIZATION_URI"));
        return;
    }
    task.Reject(env, CreateJsError(env, AbilityErrorCode::ERROR_CODE_INNER));
    return;
}

static void ResolveGrantUriPermissionWithAppIndexTask(napi_env env, NapiAsyncTask &task, int32_t errCode)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "ResolveGrantUriPermissionWithAppIndexTask");
    if (errCode == ERR_OK) {
        task.ResolveWithNoError(env, CreateJsUndefined(env));
        return;
    }
    if (errCode == AAFwk::CHECK_PERMISSION_FAILED || errCode == AAFwk::ERR_CODE_INVALID_URI_FLAG ||
        errCode == AAFwk::ERR_CODE_INVALID_URI_TYPE || errCode == AAFwk::ERR_CODE_GRANT_URI_PERMISSION ||
        errCode == AAFwk::ERR_GET_TARGET_BUNDLE_INFO_FAILED) {
        task.Reject(env, CreateJsErrorByNativeErr(env, errCode, "ohos.permission.PROXY_AUTHORIZATION_URI"));
        return;
    }
    task.Reject(env, CreateJsError(env, AbilityErrorCode::ERROR_CODE_INNER));
    return;
}

static void ResolveRevokeUriPermissionTask(napi_env env, NapiAsyncTask &task, int32_t errCode)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "ResolveRevokeUriPermissionTask");
    if (errCode == ERR_OK) {
        task.ResolveWithNoError(env, CreateJsUndefined(env));
        return;
    }
    if (errCode == AAFwk::ERR_CODE_INVALID_URI_TYPE || errCode == AAFwk::ERR_CODE_GRANT_URI_PERMISSION) {
        task.Reject(env, CreateJsErrorByNativeErr(env, errCode));
        return;
    }
    task.Reject(env, CreateJsError(env, AbilityErrorCode::ERROR_CODE_INNER));
    return;
}

static void ResolveRevokeUriPermissionWithAppIndexTask(napi_env env, NapiAsyncTask &task, int32_t errCode)
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "ResolveRevokeUriPermissionWithAppIndexTask");
    if (errCode == ERR_OK) {
        task.ResolveWithNoError(env, CreateJsUndefined(env));
        return;
    }
    if (errCode == AAFwk::ERR_CODE_INVALID_URI_TYPE || errCode == AAFwk::ERR_CODE_GRANT_URI_PERMISSION ||
        errCode == AAFwk::ERR_GET_TARGET_BUNDLE_INFO_FAILED) {
        task.Reject(env, CreateJsErrorByNativeErr(env, errCode));
        return;
    }
    task.Reject(env, CreateJsError(env, AbilityErrorCode::ERROR_CODE_INNER));
    return;
}

static bool ParseGrantUriPermissionParams(napi_env env, NapiCallbackInfo &info, UriPermissionParam &param)
{
    // only support 3 or 4 params
    if (info.argc < argCountThree) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "param number invalid");
        ThrowTooFewParametersError(env);
        return false;
    }
    if (!OHOS::AppExecFwk::UnwrapStringFromJS2(env, info.argv[0], param.uriStr)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "invalid uriStr");
        ThrowInvalidParamError(env, "Parse param uri failed, uri must be string.");
        return false;
    }
    if (!OHOS::AppExecFwk::UnwrapInt32FromJS2(env, info.argv[1], param.flag)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "flag invalid.");
        ThrowInvalidParamError(env, "Parse param flag failed, flag must be number.");
        return false;
    }
    if (!OHOS::AppExecFwk::UnwrapStringFromJS2(env, info.argv[argCountTwo], param.bundleName)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "targetBundleName invalid");
        ThrowInvalidParamError(env, "Parse param targetBundleName failed, targetBundleName must be string.");
        return false;
    }
    if (info.argc >= argCountFour) {
        // process param index or callback
        if (CheckTypeForNapiValue(env, info.argv[argCountThree], napi_function)) {
            return true;
        }
        if (!CheckTypeForNapiValue(env, info.argv[argCountThree], napi_number) ||
            !OHOS::AppExecFwk::UnwrapInt32FromJS2(env, info.argv[argCountThree], param.appIndex)) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "appIndex invalid");
            ThrowInvalidParamError(env, "Parse param appCloneIndex failed, appCloneIndex must be number.");
            return false;
        }
        if (param.appIndex < 0) {
            ThrowInvalidParamError(env, "Param appCloneIndex is invalid, the value less than 0.");
            return false;
        }
        param.hasAppIndex = true;
    }
    return true;
}

static bool ParseRevokeUriPermissionParams(napi_env env, NapiCallbackInfo &info, UriPermissionParam &param)
{
    // only support 2 or 3 params
    if (info.argc < argCountTwo) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Invalid args");
        ThrowTooFewParametersError(env);
        return false;
    }
    if (!OHOS::AppExecFwk::UnwrapStringFromJS2(env, info.argv[0], param.uriStr)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "invalid uriStr");
        ThrowInvalidParamError(env, "Parse param uri failed, uri must be string.");
        return false;
    }
    if (!OHOS::AppExecFwk::UnwrapStringFromJS2(env, info.argv[1], param.bundleName)) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "bundleName invalid");
        ThrowInvalidParamError(env, "Parse param bundleName failed, bundleName must be string.");
        return false;
    }
    if (info.argc >= argCountThree) {
        // process param index or callback
        if (CheckTypeForNapiValue(env, info.argv[argCountTwo], napi_function)) {
            return true;
        }
        if (!CheckTypeForNapiValue(env, info.argv[argCountTwo], napi_number) ||
            !OHOS::AppExecFwk::UnwrapInt32FromJS2(env, info.argv[argCountTwo], param.appIndex)) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "appCloneIndex invalid");
            ThrowInvalidParamError(env, "Parse param appCloneIndex failed, appCloneIndex must be number.");
            return false;
        }
        if (param.appIndex < 0) {
            ThrowInvalidParamError(env, "Param appCloneIndex is invalid, the value less than 0.");
            return false;
        }
        param.hasAppIndex = true;
    }
    return true;
}
}
class JsUriPermMgr {
public:
    JsUriPermMgr() = default;
    ~JsUriPermMgr() = default;

    static void Finalizer(napi_env env, void* data, void* hint)
    {
        TAG_LOGI(AAFwkTag::URIPERMMGR, "call");
        std::unique_ptr<JsUriPermMgr>(static_cast<JsUriPermMgr*>(data));
    }

    static napi_value GrantUriPermission(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsUriPermMgr, OnGrantUriPermission);
    }

    static napi_value RevokeUriPermission(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsUriPermMgr, OnRevokeUriPermission);
    }

private:
    napi_value OnGrantUriPermission(napi_env env, NapiCallbackInfo& info)
    {
        TAG_LOGD(AAFwkTag::URIPERMMGR, "start");
        UriPermissionParam param;
        if (!ParseGrantUriPermissionParams(env, info, param)) {
            return CreateJsUndefined(env);
        }
        auto selfToken = IPCSkeleton::GetSelfTokenID();
        if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken)) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "app not system-app");
            ThrowError(env, AbilityErrorCode::ERROR_CODE_NOT_SYSTEM_APP);
            return CreateJsUndefined(env);
        }
        NapiAsyncTask::CompleteCallback complete =
        [param](napi_env env, NapiAsyncTask& task, int32_t status) {
            Uri uri(param.uriStr);
            int errCode = AAFwk::UriPermissionManagerClient::GetInstance().GrantUriPermission(uri,
                param.flag, param.bundleName, param.appIndex);
            TAG_LOGI(AAFwkTag::URIPERMMGR, "GrantUriPermission, errCode is %{public}d", errCode);
            if (param.hasAppIndex) {
                return ResolveGrantUriPermissionWithAppIndexTask(env, task, errCode);
            }
            return ResolveGrantUriPermissionTask(env, task, errCode);
        };
        napi_value lastParam = (info.argc >= argCountFour && !param.hasAppIndex) ? info.argv[argCountThree] : nullptr;
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleHighQos("JsUriPermMgr::OnGrantUriPermission",
            env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    napi_value OnRevokeUriPermission(napi_env env, NapiCallbackInfo& info)
    {
        TAG_LOGD(AAFwkTag::URIPERMMGR, "start");
        UriPermissionParam param;
        if (!ParseRevokeUriPermissionParams(env, info, param)) {
            return CreateJsUndefined(env);
        }
        auto selfToken = IPCSkeleton::GetSelfTokenID();
        if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken)) {
            TAG_LOGE(AAFwkTag::URIPERMMGR, "app not system-app");
            ThrowError(env, AbilityErrorCode::ERROR_CODE_NOT_SYSTEM_APP);
            return CreateJsUndefined(env);
        }
        NapiAsyncTask::CompleteCallback complete =
        [param](napi_env env, NapiAsyncTask& task, int32_t status) {
            Uri uri(param.uriStr);
            auto errCode = AAFwk::UriPermissionManagerClient::GetInstance().RevokeUriPermissionManually(uri,
                param.bundleName, param.appIndex);
            TAG_LOGD(AAFwkTag::URIPERMMGR, "errCode: %{public}d", errCode);
            if (param.hasAppIndex) {
                return ResolveRevokeUriPermissionWithAppIndexTask(env, task, errCode);
            }
            return ResolveRevokeUriPermissionTask(env, task, errCode);
        };
        napi_value lastParam = (info.argc >= argCountThree && !param.hasAppIndex) ? info.argv[argCountTwo] : nullptr;
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleHighQos("JsUriPermMgr::OnRevokeUriPermission",
            env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
        return result;
    }
};

napi_value CreateJsUriPermMgr(napi_env env, napi_value exportObj)
{
    TAG_LOGD(AAFwkTag::URIPERMMGR, "call");
    if (env == nullptr || exportObj == nullptr) {
        TAG_LOGI(AAFwkTag::URIPERMMGR, "Invalid param");
        return nullptr;
    }

    std::unique_ptr<JsUriPermMgr> jsUriPermMgr = std::make_unique<JsUriPermMgr>();
    napi_wrap(env, exportObj, jsUriPermMgr.release(), JsUriPermMgr::Finalizer, nullptr, nullptr);

    const char *moduleName = "JsUriPermMgr";
    BindNativeFunction(env, exportObj, "grantUriPermission", moduleName, JsUriPermMgr::GrantUriPermission);
    BindNativeFunction(env, exportObj, "revokeUriPermission", moduleName, JsUriPermMgr::RevokeUriPermission);
    return CreateJsUndefined(env);
}
}  // namespace AbilityRuntime
}  // namespace OHOS
