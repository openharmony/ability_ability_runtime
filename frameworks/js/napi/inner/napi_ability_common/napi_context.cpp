/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "napi_context.h"

#include <cstring>
#include <uv.h>

#include "napi_common_ability.h"
#include "napi_context_helper.h"
#include "ability_util.h"
#include "ability_process.h"
#include "directory_ex.h"
#include "feature_ability_common.h"
#include "file_ex.h"
#include "hilog_tag_wrapper.h"
#include "js_napi_common_ability.h"
#include "permission_list_state.h"
#include "securec.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace AppExecFwk {
napi_value ContextConstructor(napi_env env, napi_callback_info info)
{
    napi_value jsthis = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &jsthis, nullptr));

    napi_value value = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, false, &value));

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("stageMode", value),
    };
    NAPI_CALL(env, napi_define_properties(env, jsthis, sizeof(desc) / sizeof(desc[0]), desc));

    return jsthis;
}

struct OnRequestPermissionsData {
    int requestCode = 0;
    std::vector<std::string> permissions;
    std::vector<int> grantResults;
    uv_work_t uvWork{};
    NapiAsyncTask *napiAsyncTask = nullptr;
    napi_env env = nullptr;

    ~OnRequestPermissionsData()
    {
        if (napiAsyncTask) {
            delete napiAsyncTask;
        }
    }

    static void WorkCallback(uv_work_t* work)
    {
        TAG_LOGI(AAFwkTag::JSNAPI, "called");
    }

    static void AfterWorkCallback(uv_work_t* work, int status)
    {
        TAG_LOGD(AAFwkTag::JSNAPI, "called");
        if (work == nullptr) {
            TAG_LOGE(AAFwkTag::JSNAPI, "null work");
            return;
        }
        if (work->data == nullptr) {
            TAG_LOGE(AAFwkTag::JSNAPI, "null data");
            return;
        }
        std::unique_ptr<OnRequestPermissionsData> data{static_cast<OnRequestPermissionsData *>(work->data)};
        auto env = data->env;
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        napi_value object = nullptr;
        napi_create_object(env, &object);
        napi_set_named_property(env, object, "requestCode", CreateJsValue(env, data->requestCode));
        napi_set_named_property(env, object, "permissions", CreateNativeArray(env, data->permissions));
        napi_set_named_property(env, object, "authResults", CreateNativeArray(env, data->grantResults));
        data->napiAsyncTask->Resolve(env, object);
        napi_close_handle_scope(env, scope);
    }
};

EXTERN_C_START
void CallOnRequestPermissionsFromUserResult(int requestCode, const std::vector<std::string> &permissions,
    const std::vector<int> &grantResults, CallbackInfo callbackInfo)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    if (permissions.empty()) {
        TAG_LOGE(AAFwkTag::JSNAPI, "empty permissions");
        return;
    }
    if (permissions.size() != grantResults.size()) {
        TAG_LOGE(AAFwkTag::JSNAPI, "permissions size not match");
        return;
    }
    if (callbackInfo.env == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null env");
        return;
    }
    if (callbackInfo.napiAsyncTask == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null napiAsyncTask");
        return;
    }

    uv_loop_t *loop = nullptr;
    napi_get_uv_event_loop(callbackInfo.env, &loop);
    if (loop == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null loop");
        return;
    }

    auto reqData = std::make_unique<OnRequestPermissionsData>();
    reqData->permissions = permissions;
    reqData->grantResults = grantResults;
    reqData->requestCode = requestCode;
    reqData->env = callbackInfo.env;
    reqData->napiAsyncTask = callbackInfo.napiAsyncTask;
    reqData->uvWork.data = static_cast<void *>(reqData.get());

    int rev = uv_queue_work_with_qos(loop, &(reqData->uvWork),
        OnRequestPermissionsData::WorkCallback, OnRequestPermissionsData::AfterWorkCallback, uv_qos_user_initiated);
    if (rev == 0) {
        (void)reqData.release();
    }
}
EXTERN_C_END

CallingBundleCB *CreateCallingBundleCBInfo(napi_env env)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    napi_value global = nullptr;
    NAPI_CALL(env, napi_get_global(env, &global));

    napi_value abilityObj = nullptr;
    NAPI_CALL(env, napi_get_named_property(env, global, "ability", &abilityObj));

    Ability *ability = nullptr;
    NAPI_CALL(env, napi_get_value_external(env, abilityObj, reinterpret_cast<void **>(&ability)));

    CallingBundleCB *callingBundleCB = new (std::nothrow) CallingBundleCB;
    if (callingBundleCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null callingBundleCB");
        return nullptr;
    }
    callingBundleCB->cbBase.cbInfo.env = env;
    callingBundleCB->cbBase.asyncWork = nullptr;
    callingBundleCB->cbBase.deferred = nullptr;
    callingBundleCB->cbBase.ability = ability;

    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return callingBundleCB;
}

void GetCallingBundleExecuteCB(napi_env env, void *data)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "execute");
    CallingBundleCB *callingBundleCB = static_cast<CallingBundleCB *>(data);
    if (callingBundleCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null callingBundleCB");
        return;
    }

    callingBundleCB->cbBase.errCode = NAPI_ERR_NO_ERROR;
    if (callingBundleCB->cbBase.ability == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null ability");
        callingBundleCB->cbBase.errCode = NAPI_ERR_ACE_ABILITY;
        return;
    }

    callingBundleCB->callingBundleName = callingBundleCB->cbBase.ability->GetCallingBundle();
    TAG_LOGI(AAFwkTag::JSNAPI, "execute end");
}

napi_value WrapCallingBundle(napi_env env, const CallingBundleCB *callingBundleCB)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    if (callingBundleCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null callingBundleCB");
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, callingBundleCB->callingBundleName.c_str(), NAPI_AUTO_LENGTH, &result));
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return result;
}

void GetCallingBundleAsyncCompleteCB(napi_env env, napi_status status, void *data)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "complete");
    CallingBundleCB *callingBundleCB = static_cast<CallingBundleCB *>(data);
    napi_value callback = nullptr;
    napi_value undefined = nullptr;
    napi_value result[ARGS_TWO] = {nullptr};
    napi_value callResult = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
    result[PARAM0] = GetCallbackErrorValue(env, callingBundleCB->cbBase.errCode);
    if (callingBundleCB->cbBase.errCode == NAPI_ERR_NO_ERROR) {
        result[PARAM1] = WrapCallingBundle(env, callingBundleCB);
    } else {
        result[PARAM1] = WrapUndefinedToJS(env);
    }
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, callingBundleCB->cbBase.cbInfo.callback, &callback));
    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, ARGS_TWO, &result[PARAM0], &callResult));

    if (callingBundleCB->cbBase.cbInfo.callback != nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, callingBundleCB->cbBase.cbInfo.callback));
    }
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, callingBundleCB->cbBase.asyncWork));
    delete callingBundleCB;
    callingBundleCB = nullptr;
    TAG_LOGI(AAFwkTag::JSNAPI, "complete end");
}

void GetCallingBundlePromiseCompleteCB(napi_env env, napi_status status, void *data)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "complete");
    CallingBundleCB *callingBundleCB = static_cast<CallingBundleCB *>(data);
    napi_value result = nullptr;
    if (callingBundleCB->cbBase.errCode == NAPI_ERR_NO_ERROR) {
        result = WrapCallingBundle(env, callingBundleCB);
        napi_resolve_deferred(env, callingBundleCB->cbBase.deferred, result);
    } else {
        result = GetCallbackErrorValue(env, callingBundleCB->cbBase.errCode);
        napi_reject_deferred(env, callingBundleCB->cbBase.deferred, result);
    }

    napi_delete_async_work(env, callingBundleCB->cbBase.asyncWork);
    delete callingBundleCB;
    callingBundleCB = nullptr;
    TAG_LOGI(AAFwkTag::JSNAPI, "complete end");
}

napi_value GetCallingBundleAsync(
    napi_env env, napi_value *args, const size_t argCallback, CallingBundleCB *callingBundleCB)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    if (args == nullptr || callingBundleCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null param");
        return nullptr;
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[argCallback], &valuetype));
    if (valuetype == napi_function) {
        NAPI_CALL(env, napi_create_reference(env, args[argCallback], 1, &callingBundleCB->cbBase.cbInfo.callback));
    }
    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            GetCallingBundleExecuteCB,
            GetCallingBundleAsyncCompleteCB,
            static_cast<void *>(callingBundleCB),
            &callingBundleCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, callingBundleCB->cbBase.asyncWork, napi_qos_user_initiated));
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return result;
}

napi_value GetCallingBundlePromise(napi_env env, CallingBundleCB *callingBundleCB)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "promise");
    if (callingBundleCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null callingBundleCB");
        return nullptr;
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    napi_deferred deferred;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    callingBundleCB->cbBase.deferred = deferred;

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            GetCallingBundleExecuteCB,
            GetCallingBundlePromiseCompleteCB,
            static_cast<void *>(callingBundleCB),
            &callingBundleCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, callingBundleCB->cbBase.asyncWork, napi_qos_user_initiated));
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return promise;
}

napi_value GetCallingBundleWrap(napi_env env, napi_callback_info info, CallingBundleCB *callingBundleCB)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    if (callingBundleCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null callingBundleCB");
        return nullptr;
    }

    size_t argcAsync = 1;
    const size_t argcPromise = 0;
    const size_t argCountWithAsync = argcPromise + ARGS_ASYNC_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    napi_value ret = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, nullptr, nullptr));
    if (argcAsync > argCountWithAsync || argcAsync > ARGS_MAX_COUNT) {
        TAG_LOGE(AAFwkTag::JSNAPI, "invalid argc");
        return nullptr;
    }

    if (argcAsync > argcPromise) {
        ret = GetCallingBundleAsync(env, args, 0, callingBundleCB);
    } else {
        ret = GetCallingBundlePromise(env, callingBundleCB);
    }
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return ret;
}

GetOrCreateLocalDirCB *CreateGetOrCreateLocalDirCBInfo(napi_env env)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    napi_value global = nullptr;
    NAPI_CALL(env, napi_get_global(env, &global));

    napi_value abilityObj = nullptr;
    NAPI_CALL(env, napi_get_named_property(env, global, "ability", &abilityObj));

    Ability *ability = nullptr;
    NAPI_CALL(env, napi_get_value_external(env, abilityObj, reinterpret_cast<void **>(&ability)));

    GetOrCreateLocalDirCB *getOrCreateLocalDirCB = new (std::nothrow) GetOrCreateLocalDirCB;
    if (getOrCreateLocalDirCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null getOrCreateLocalDirCB");
        return nullptr;
    }
    getOrCreateLocalDirCB->cbBase.cbInfo.env = env;
    getOrCreateLocalDirCB->cbBase.asyncWork = nullptr;
    getOrCreateLocalDirCB->cbBase.deferred = nullptr;
    getOrCreateLocalDirCB->cbBase.ability = ability;

    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return getOrCreateLocalDirCB;
}

void GetOrCreateLocalDirExecuteCB(napi_env env, void *data)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "execute");
    GetOrCreateLocalDirCB *getOrCreateLocalDirCB = static_cast<GetOrCreateLocalDirCB *>(data);
    if (getOrCreateLocalDirCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null getOrCreateLocalDirCB");
        return;
    }

    getOrCreateLocalDirCB->cbBase.errCode = NAPI_ERR_NO_ERROR;
    if (getOrCreateLocalDirCB->cbBase.ability == nullptr ||
        getOrCreateLocalDirCB->cbBase.ability->GetAbilityContext() == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null ability or abilityContext");
        getOrCreateLocalDirCB->cbBase.errCode = NAPI_ERR_ACE_ABILITY;
        return;
    }

    getOrCreateLocalDirCB->rootDir = getOrCreateLocalDirCB->cbBase.ability->GetAbilityContext()->GetBaseDir();
    TAG_LOGI(AAFwkTag::JSNAPI, "rootDir:%{public}s",
             getOrCreateLocalDirCB->rootDir.c_str());
    if (!OHOS::FileExists(getOrCreateLocalDirCB->rootDir)) {
        TAG_LOGI(AAFwkTag::JSNAPI, "create dir");
        OHOS::ForceCreateDirectory(getOrCreateLocalDirCB->rootDir);
        OHOS::ChangeModeDirectory(getOrCreateLocalDirCB->rootDir, MODE);
    }
    TAG_LOGI(AAFwkTag::JSNAPI, "execute end");
}

napi_value WrapGetOrCreateLocalDir(napi_env env, const GetOrCreateLocalDirCB *getOrCreateLocalDirCB)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    if (getOrCreateLocalDirCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null getOrCreateLocalDirCB");
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, getOrCreateLocalDirCB->rootDir.c_str(), NAPI_AUTO_LENGTH, &result));
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return result;
}

void GetOrCreateLocalDirAsyncCompleteCB(napi_env env, napi_status status, void *data)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "complete");
    GetOrCreateLocalDirCB *getOrCreateLocalDirCB = static_cast<GetOrCreateLocalDirCB *>(data);
    napi_value callback = nullptr;
    napi_value undefined = nullptr;
    napi_value result[ARGS_TWO] = {nullptr};
    napi_value callResult = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
    result[PARAM0] = GetCallbackErrorValue(env, getOrCreateLocalDirCB->cbBase.errCode);
    if (getOrCreateLocalDirCB->cbBase.errCode == NAPI_ERR_NO_ERROR) {
        result[PARAM1] = WrapGetOrCreateLocalDir(env, getOrCreateLocalDirCB);
    } else {
        result[PARAM1] = WrapUndefinedToJS(env);
    }
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, getOrCreateLocalDirCB->cbBase.cbInfo.callback, &callback));
    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, ARGS_TWO, &result[PARAM0], &callResult));

    if (getOrCreateLocalDirCB->cbBase.cbInfo.callback != nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, getOrCreateLocalDirCB->cbBase.cbInfo.callback));
    }
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, getOrCreateLocalDirCB->cbBase.asyncWork));
    delete getOrCreateLocalDirCB;
    getOrCreateLocalDirCB = nullptr;
    TAG_LOGI(AAFwkTag::JSNAPI, "complete end");
}

void GetOrCreateLocalDirPromiseCompleteCB(napi_env env, napi_status status, void *data)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "complete");
    GetOrCreateLocalDirCB *getOrCreateLocalDirCB = static_cast<GetOrCreateLocalDirCB *>(data);
    napi_value result = nullptr;
    if (getOrCreateLocalDirCB->cbBase.errCode == NAPI_ERR_NO_ERROR) {
        result = WrapGetOrCreateLocalDir(env, getOrCreateLocalDirCB);
        napi_resolve_deferred(env, getOrCreateLocalDirCB->cbBase.deferred, result);
    } else {
        result = GetCallbackErrorValue(env, getOrCreateLocalDirCB->cbBase.errCode);
        napi_reject_deferred(env, getOrCreateLocalDirCB->cbBase.deferred, result);
    }

    napi_delete_async_work(env, getOrCreateLocalDirCB->cbBase.asyncWork);
    delete getOrCreateLocalDirCB;
    getOrCreateLocalDirCB = nullptr;
    TAG_LOGI(AAFwkTag::JSNAPI, "complete end");
}

napi_value GetOrCreateLocalDirAsync(
    napi_env env, napi_value *args, const size_t argCallback, GetOrCreateLocalDirCB *getOrCreateLocalDirCB)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    if (args == nullptr || getOrCreateLocalDirCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null param");
        return nullptr;
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[argCallback], &valuetype));
    if (valuetype == napi_function) {
        NAPI_CALL(
            env, napi_create_reference(env, args[argCallback], 1, &getOrCreateLocalDirCB->cbBase.cbInfo.callback));
    }
    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            GetOrCreateLocalDirExecuteCB,
            GetOrCreateLocalDirAsyncCompleteCB,
            static_cast<void *>(getOrCreateLocalDirCB),
            &getOrCreateLocalDirCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, getOrCreateLocalDirCB->cbBase.asyncWork));
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return result;
}

napi_value GetOrCreateLocalDirPromise(napi_env env, GetOrCreateLocalDirCB *getOrCreateLocalDirCB)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "promise");
    if (getOrCreateLocalDirCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null getOrCreateLocalDirCB");
        return nullptr;
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    napi_deferred deferred;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    getOrCreateLocalDirCB->cbBase.deferred = deferred;

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            GetOrCreateLocalDirExecuteCB,
            GetOrCreateLocalDirPromiseCompleteCB,
            static_cast<void *>(getOrCreateLocalDirCB),
            &getOrCreateLocalDirCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, getOrCreateLocalDirCB->cbBase.asyncWork));
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return promise;
}

napi_value GetOrCreateLocalDirWrap(napi_env env, napi_callback_info info, GetOrCreateLocalDirCB *getOrCreateLocalDirCB)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    if (getOrCreateLocalDirCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null getOrCreateLocalDirCB");
        return nullptr;
    }

    size_t argcAsync = 1;
    const size_t argcPromise = 0;
    const size_t argCountWithAsync = argcPromise + ARGS_ASYNC_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    napi_value ret = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, nullptr, nullptr));
    if (argcAsync > argCountWithAsync || argcAsync > ARGS_MAX_COUNT) {
        TAG_LOGE(AAFwkTag::JSNAPI, "invalid argc");
        return nullptr;
    }

    if (argcAsync > argcPromise) {
        ret = GetOrCreateLocalDirAsync(env, args, 0, getOrCreateLocalDirCB);
    } else {
        ret = GetOrCreateLocalDirPromise(env, getOrCreateLocalDirCB);
    }
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return ret;
}

napi_value NAPI_GetBundleName(napi_env env, napi_callback_info info)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    AsyncJSCallbackInfo *asyncCallbackInfo = CreateAsyncJSCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null asyncCallbackInfo");
        return WrapVoidToJS(env);
    }

    napi_value ret = NAPI_GetBundleNameWrap(env, info, asyncCallbackInfo);
    if (ret == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null ret");
        FreeAsyncJSCallbackInfo(&asyncCallbackInfo);
        ret = WrapVoidToJS(env);
    }
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return ret;
}

napi_value NAPI_GetApplicationInfo(napi_env env, napi_callback_info info)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    AppInfoCB *appInfoCB = CreateAppInfoCBInfo(env);
    if (appInfoCB == nullptr) {
        return WrapVoidToJS(env);
    }

    napi_value ret = GetApplicationInfoWrap(env, info, appInfoCB);
    if (ret == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null ret");
        if (appInfoCB != nullptr) {
            delete appInfoCB;
            appInfoCB = nullptr;
        }
        ret = WrapVoidToJS(env);
    }
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return ret;
}

napi_value NAPI_GetProcessInfo(napi_env env, napi_callback_info info)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    ProcessInfoCB *processInfoCB = CreateProcessInfoCBInfo(env);
    if (processInfoCB == nullptr) {
        return WrapVoidToJS(env);
    }

    processInfoCB->cbBase.errCode = NAPI_ERR_NO_ERROR;
    napi_value ret = GetProcessInfoWrap(env, info, processInfoCB);
    if (ret == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null ret");
        if (processInfoCB != nullptr) {
            delete processInfoCB;
            processInfoCB = nullptr;
        }
        ret = WrapVoidToJS(env);
    }
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return ret;
}

napi_value NAPI_GetElementName(napi_env env, napi_callback_info info)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    ElementNameCB *elementNameCB = CreateElementNameCBInfo(env);
    if (elementNameCB == nullptr) {
        return WrapVoidToJS(env);
    }

    elementNameCB->cbBase.errCode = NAPI_ERR_NO_ERROR;
    napi_value ret = GetElementNameWrap(env, info, elementNameCB);
    if (ret == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null ret");
        if (elementNameCB != nullptr) {
            delete elementNameCB;
            elementNameCB = nullptr;
        }
        ret = WrapVoidToJS(env);
    }
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return ret;
}

napi_value NAPI_GetProcessName(napi_env env, napi_callback_info info)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    ProcessNameCB *processNameCB = CreateProcessNameCBInfo(env);
    if (processNameCB == nullptr) {
        return WrapVoidToJS(env);
    }

    processNameCB->cbBase.errCode = NAPI_ERR_NO_ERROR;
    napi_value ret = GetProcessNameWrap(env, info, processNameCB);
    if (ret == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null ret");
        if (processNameCB != nullptr) {
            delete processNameCB;
            processNameCB = nullptr;
        }
        ret = WrapVoidToJS(env);
    }
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return ret;
}

napi_value NAPI_GetCallingBundle(napi_env env, napi_callback_info info)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    CallingBundleCB *callingBundleCB = CreateCallingBundleCBInfo(env);
    if (callingBundleCB == nullptr) {
        return WrapVoidToJS(env);
    }

    callingBundleCB->cbBase.errCode = NAPI_ERR_NO_ERROR;
    napi_value ret = GetCallingBundleWrap(env, info, callingBundleCB);
    if (ret == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null ret");
        if (callingBundleCB != nullptr) {
            delete callingBundleCB;
            callingBundleCB = nullptr;
        }
        ret = WrapVoidToJS(env);
    }
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return ret;
}

napi_value NAPI_GetOrCreateLocalDir(napi_env env, napi_callback_info info)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    GetOrCreateLocalDirCB *getOrCreateLocalDirCB = CreateGetOrCreateLocalDirCBInfo(env);
    if (getOrCreateLocalDirCB == nullptr) {
        return WrapVoidToJS(env);
    }

    getOrCreateLocalDirCB->cbBase.errCode = NAPI_ERR_NO_ERROR;
    napi_value ret = GetOrCreateLocalDirWrap(env, info, getOrCreateLocalDirCB);
    if (ret == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null ret");
        if (getOrCreateLocalDirCB != nullptr) {
            delete getOrCreateLocalDirCB;
            getOrCreateLocalDirCB = nullptr;
        }
        ret = WrapVoidToJS(env);
    }
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return ret;
}

napi_value NAPI_GetDatabaseDirSync(napi_env env, napi_callback_info info)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    DatabaseDirCB *getDatabaseDirCB = CreateGetDatabaseDirCBInfo(env);
    if (getDatabaseDirCB == nullptr) {
        return WrapVoidToJS(env);
    }

    getDatabaseDirCB->cbBase.errCode = NAPI_ERR_NO_ERROR;
    napi_value ret = GetDatabaseDirWrap(env, info, getDatabaseDirCB);

    delete getDatabaseDirCB;
    getDatabaseDirCB = nullptr;

    if (ret == nullptr) {
        ret = WrapVoidToJS(env);
        TAG_LOGE(AAFwkTag::JSNAPI, "null ret");
    } else {
        TAG_LOGI(AAFwkTag::JSNAPI, "end");
    }
    return ret;
}

napi_value NAPI_GetPreferencesDirSync(napi_env env, napi_callback_info info)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    PreferencesDirCB *preferencesDirCB = CreateGetPreferencesDirCBInfo(env);
    if (preferencesDirCB == nullptr) {
        return WrapVoidToJS(env);
    }

    preferencesDirCB->cbBase.errCode = NAPI_ERR_NO_ERROR;
    napi_value ret = GetPreferencesDirWrap(env, info, preferencesDirCB);

    delete preferencesDirCB;
    preferencesDirCB = nullptr;

    if (ret == nullptr) {
        ret = WrapVoidToJS(env);
        TAG_LOGE(AAFwkTag::JSNAPI, "null ret");
    } else {
        TAG_LOGI(AAFwkTag::JSNAPI, "end");
    }
    return ret;
}

napi_value NAPI_IsUpdatingConfigurations(napi_env env, napi_callback_info info)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    return NAPI_IsUpdatingConfigurationsCommon(env, info, AbilityType::PAGE);
}

napi_value NAPI_GetExternalCacheDir(napi_env env, napi_callback_info info)
{
    TAG_LOGD(AAFwkTag::JSNAPI, "called");
    return NAPI_GetExternalCacheDirCommon(env, info, AbilityType::PAGE);
}

napi_value NAPI_PrintDrawnCompleted(napi_env env, napi_callback_info info)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    return NAPI_PrintDrawnCompletedCommon(env, info, AbilityType::PAGE);
}

napi_value NAPI_SetDisplayOrientation(napi_env env, napi_callback_info info)
{
#ifdef SUPPORT_GRAPHICS
    TAG_LOGD(AAFwkTag::JSNAPI, "called");

    AsyncJSCallbackInfo *asyncCallbackInfo = CreateAsyncJSCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        TAG_LOGW(AAFwkTag::JSNAPI, "null asyncCallbackInfo");
        return WrapVoidToJS(env);
    }

    napi_value rev = NAPI_SetDisplayOrientationWrap(env, info, asyncCallbackInfo);
    if (rev == nullptr) {
        FreeAsyncJSCallbackInfo(&asyncCallbackInfo);
        rev = WrapVoidToJS(env);
    }
    return rev;
#else
   return WrapVoidToJS(env);
#endif
}

napi_value NAPI_GetDisplayOrientation(napi_env env, napi_callback_info info)
{
#ifdef SUPPORT_GRAPHICS
    TAG_LOGD(AAFwkTag::JSNAPI, "called");
    return NAPI_GetDisplayOrientationCommon(env, info, AbilityType::PAGE);
#else
   return 0;
#endif
}

napi_value ContextPermissionInit(napi_env env, napi_value exports)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("verifySelfPermission", NAPI_VerifySelfPermission),
        DECLARE_NAPI_FUNCTION("requestPermissionsFromUser", NAPI_RequestPermissionsFromUser),
        DECLARE_NAPI_FUNCTION("getBundleName", NAPI_GetBundleName),
        DECLARE_NAPI_FUNCTION("verifyPermission", NAPI_VerifyPermission),
        DECLARE_NAPI_FUNCTION("getApplicationInfo", NAPI_GetApplicationInfo),
        DECLARE_NAPI_FUNCTION("getProcessInfo", NAPI_GetProcessInfo),
        DECLARE_NAPI_FUNCTION("getElementName", NAPI_GetElementName),
        DECLARE_NAPI_FUNCTION("getProcessName", NAPI_GetProcessName),
        DECLARE_NAPI_FUNCTION("getCallingBundle", NAPI_GetCallingBundle),
        DECLARE_NAPI_FUNCTION("getOrCreateLocalDir", NAPI_GetOrCreateLocalDir),
        DECLARE_NAPI_FUNCTION("getFilesDir", NAPI_GetFilesDir),
        DECLARE_NAPI_FUNCTION("isUpdatingConfigurations", NAPI_IsUpdatingConfigurations),
        DECLARE_NAPI_FUNCTION("printDrawnCompleted", NAPI_PrintDrawnCompleted),
        DECLARE_NAPI_FUNCTION("getDatabaseDirSync", NAPI_GetDatabaseDirSync),
        DECLARE_NAPI_FUNCTION("getPreferencesDirSync", NAPI_GetPreferencesDirSync),
        DECLARE_NAPI_FUNCTION("getCacheDir", NAPI_GetCacheDir),
        DECLARE_NAPI_FUNCTION("getAppType", NAPI_GetCtxAppType),
        DECLARE_NAPI_FUNCTION("getHapModuleInfo", NAPI_GetCtxHapModuleInfo),
        DECLARE_NAPI_FUNCTION("getAppVersionInfo", NAPI_GetAppVersionInfo),
        DECLARE_NAPI_FUNCTION("getApplicationContext", NAPI_GetApplicationContext),
        DECLARE_NAPI_FUNCTION("getAbilityInfo", NAPI_GetCtxAbilityInfo),
        DECLARE_NAPI_FUNCTION("setShowOnLockScreen", NAPI_SetShowOnLockScreen),
        DECLARE_NAPI_FUNCTION("getOrCreateDistributedDir", NAPI_GetOrCreateDistributedDir),
        DECLARE_NAPI_FUNCTION("setWakeUpScreen", NAPI_SetWakeUpScreen),
        DECLARE_NAPI_FUNCTION("setDisplayOrientation", NAPI_SetDisplayOrientation),
        DECLARE_NAPI_FUNCTION("getDisplayOrientation", NAPI_GetDisplayOrientation),
        DECLARE_NAPI_FUNCTION("getExternalCacheDir", NAPI_GetExternalCacheDir),
    };
    napi_value constructor;
    NAPI_CALL(env,
        napi_define_class(env,
            "context",
            NAPI_AUTO_LENGTH,
            ContextConstructor,
            nullptr,
            sizeof(properties) / sizeof(*properties),
            properties,
            &constructor));
    NAPI_CALL(env, SetGlobalClassContext(env, constructor));
    return exports;
}

napi_value NAPI_SetWakeUpScreen(napi_env env, napi_callback_info info)
{
#ifdef SUPPORT_GRAPHICS
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    SetWakeUpScreenCB *setWakeUpScreenCB = new (std::nothrow) SetWakeUpScreenCB;
    if (setWakeUpScreenCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null setWakeUpScreenCB");
        return WrapVoidToJS(env);
    }
    setWakeUpScreenCB->cbBase.cbInfo.env = env;
    setWakeUpScreenCB->cbBase.abilityType = AbilityType::PAGE;
    napi_value ret = SetWakeUpScreenWrap(env, info, setWakeUpScreenCB);
    if (ret == nullptr) {
        if (setWakeUpScreenCB != nullptr) {
            delete setWakeUpScreenCB;
            setWakeUpScreenCB = nullptr;
        }
        TAG_LOGE(AAFwkTag::JSNAPI, "setWakeUpScreenCB failed");
        ret = WrapVoidToJS(env);
    }
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return ret;
#else
   return nullptr;
#endif
}

class NapiJsContext : public JsNapiCommon {
public:
    NapiJsContext() = default;
    virtual ~NapiJsContext() = default;

    static void Finalizer(napi_env env, void *data, void *hint)
    {
        TAG_LOGD(AAFwkTag::JSNAPI, "called");
        std::unique_ptr<NapiJsContext>(static_cast<NapiJsContext*>(data));
    };

    static napi_value JsRequestPermissionsFromUser(napi_env env, napi_callback_info info);
    static napi_value JsGetBundleName(napi_env env, napi_callback_info info);
    static napi_value JsVerifyPermission(napi_env env, napi_callback_info info);
    static napi_value JsGetApplicationInfo(napi_env env, napi_callback_info info);
    static napi_value JsGetProcessInfo(napi_env env, napi_callback_info info);
    static napi_value JsGetElementName(napi_env env, napi_callback_info info);
    static napi_value JsGetProcessName(napi_env env, napi_callback_info info);
    static napi_value JsGetCallingBundle(napi_env env, napi_callback_info info);
    static napi_value JsGetOrCreateLocalDir(napi_env env, napi_callback_info info);
    static napi_value JsGetFilesDir(napi_env env, napi_callback_info info);
    static napi_value JsIsUpdatingConfigurations(napi_env env, napi_callback_info info);
    static napi_value JsPrintDrawnCompleted(napi_env env, napi_callback_info info);
    static napi_value JsGetCacheDir(napi_env env, napi_callback_info info);
    static napi_value JsGetCtxAppType(napi_env env, napi_callback_info info);
    static napi_value JsGetCtxHapModuleInfo(napi_env env, napi_callback_info info);
    static napi_value JsGetAppVersionInfo(napi_env env, napi_callback_info info);
    static napi_value JsGetApplicationContext(napi_env env, napi_callback_info info);
    static napi_value JsGetCtxAbilityInfo(napi_env env, napi_callback_info info);
    static napi_value JsSetShowOnLockScreen(napi_env env, napi_callback_info info);
    static napi_value JsGetOrCreateDistributedDir(napi_env env, napi_callback_info info);
    static napi_value JsSetWakeUpScreen(napi_env env, napi_callback_info info);
    static napi_value JsSetDisplayOrientation(napi_env env, napi_callback_info info);
    static napi_value JsGetDisplayOrientation(napi_env env, napi_callback_info info);
    static napi_value JsGetExternalCacheDir(napi_env env, napi_callback_info info);

    bool DataInit(napi_env env);

private:
#ifdef SUPPORT_GRAPHICS
    napi_value OnSetShowOnLockScreen(napi_env env, napi_callback_info info);
    napi_value OnSetWakeUpScreen(napi_env env, napi_callback_info info);
    napi_value OnSetDisplayOrientation(napi_env env, napi_callback_info info);
#endif

    napi_value OnRequestPermissionsFromUser(napi_env env, napi_callback_info info);
    napi_value OnGetBundleName(napi_env env, napi_callback_info info);
    napi_value OnVerifyPermission(napi_env env, napi_callback_info info);
    napi_value OnGetApplicationInfo(napi_env env, napi_callback_info info);
    napi_value OnGetProcessInfo(napi_env env, napi_callback_info info);
    napi_value OnGetElementName(napi_env env, napi_callback_info info);
    napi_value OnGetProcessName(napi_env env, napi_callback_info info);
    napi_value OnGetCallingBundle(napi_env env, napi_callback_info info);
    napi_value OnGetOrCreateLocalDir(napi_env env, napi_callback_info info);
};

static bool BindNapiJSContextFunction(napi_env env, napi_value object)
{
    TAG_LOGD(AAFwkTag::JSNAPI, "called");
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null object");
        return false;
    }
    const char* moduleName = "context";
    BindNativeFunction(
        env, object, "requestPermissionsFromUser", moduleName, NapiJsContext::JsRequestPermissionsFromUser);
    BindNativeFunction(env, object, "getBundleName", moduleName, NapiJsContext::JsGetBundleName);
    BindNativeFunction(env, object, "verifyPermission", moduleName, NapiJsContext::JsVerifyPermission);
    BindNativeFunction(env, object, "getApplicationInfo", moduleName, NapiJsContext::JsGetApplicationInfo);
    BindNativeFunction(env, object, "getProcessInfo", moduleName, NapiJsContext::JsGetProcessInfo);
    BindNativeFunction(env, object, "getElementName", moduleName, NapiJsContext::JsGetElementName);
    BindNativeFunction(env, object, "getProcessName", moduleName, NapiJsContext::JsGetProcessName);
    BindNativeFunction(env, object, "getCallingBundle", moduleName, NapiJsContext::JsGetCallingBundle);
    BindNativeFunction(env, object, "getOrCreateLocalDir", moduleName, NapiJsContext::JsGetOrCreateLocalDir);
    BindNativeFunction(env, object, "getFilesDir", moduleName, NapiJsContext::JsGetFilesDir);
    BindNativeFunction(env, object, "isUpdatingConfigurations", moduleName, NapiJsContext::JsIsUpdatingConfigurations);
    BindNativeFunction(env, object, "printDrawnCompleted", moduleName, NapiJsContext::JsPrintDrawnCompleted);
    BindNativeFunction(env, object, "getCacheDir", moduleName, NapiJsContext::JsGetCacheDir);
    BindNativeFunction(env, object, "getAppType", moduleName, NapiJsContext::JsGetCtxAppType);
    BindNativeFunction(env, object, "getHapModuleInfo", moduleName, NapiJsContext::JsGetCtxHapModuleInfo);
    BindNativeFunction(env, object, "getAppVersionInfo", moduleName, NapiJsContext::JsGetAppVersionInfo);
    BindNativeFunction(env, object, "getApplicationContext", moduleName, NapiJsContext::JsGetApplicationContext);
    BindNativeFunction(env, object, "getAbilityInfo", moduleName, NapiJsContext::JsGetCtxAbilityInfo);
    BindNativeFunction(env, object, "setShowOnLockScreen", moduleName, NapiJsContext::JsSetShowOnLockScreen);
    BindNativeFunction(env, object, "getOrCreateDistributedDir", moduleName,
        NapiJsContext::JsGetOrCreateDistributedDir);
    BindNativeFunction(env, object, "setWakeUpScreen", moduleName, NapiJsContext::JsSetWakeUpScreen);
    BindNativeFunction(env, object, "setDisplayOrientation", moduleName, NapiJsContext::JsSetDisplayOrientation);
    BindNativeFunction(env, object, "getDisplayOrientation", moduleName, NapiJsContext::JsGetDisplayOrientation);
    BindNativeFunction(env, object, "getExternalCacheDir", moduleName, NapiJsContext::JsGetExternalCacheDir);

    return true;
}

static napi_value ConstructNapiJSContext(napi_env env)
{
    TAG_LOGD(AAFwkTag::JSNAPI, "called");
    napi_value objContext = nullptr;
    napi_create_object(env, &objContext);
    if (objContext == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null objContext");
        return nullptr;
    }
    auto jsClass = std::make_unique<NapiJsContext>();
    if (!jsClass->DataInit(env)) {
        TAG_LOGE(AAFwkTag::JSNAPI, "NapiJsContext init failed");
        return nullptr;
    }
    napi_wrap(env, objContext, jsClass.release(), NapiJsContext::Finalizer, nullptr, nullptr);
    napi_set_named_property(env, objContext, "stageMode", CreateJsValue(env, false));
    if (!BindNapiJSContextFunction(env, objContext)) {
        TAG_LOGE(AAFwkTag::JSNAPI, "bind func failed");
        return nullptr;
    }

    return objContext;
}

napi_value CreateNapiJSContext(napi_env env)
{
    TAG_LOGD(AAFwkTag::JSNAPI, "called");
    auto jsObj = ConstructNapiJSContext(env);
    if (jsObj == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null obj");
        return CreateJsUndefined(env);
    }

    return jsObj;
}

napi_value NapiJsContext::JsRequestPermissionsFromUser(napi_env env, napi_callback_info info)
{
    CHECK_POINTER_AND_RETURN_LOG(env, nullptr, "but input parameters env is nullptr");
    CHECK_POINTER_AND_RETURN_LOG(info, nullptr, "but input parameters info is nullptr");

    auto object = CheckParamsAndGetThis<NapiJsContext>(env, info);
    CHECK_POINTER_AND_RETURN_LOG(object, CreateJsUndefined(env), "CheckParamsAndGetThis return nullptr");

    return object->OnRequestPermissionsFromUser(env, info);
}

napi_value NapiJsContext::JsGetBundleName(napi_env env, napi_callback_info info)
{
    CHECK_POINTER_AND_RETURN_LOG(env, nullptr, "but input parameters engine is nullptr");
    CHECK_POINTER_AND_RETURN_LOG(info, nullptr, "but input parameters info is nullptr");

    auto object = CheckParamsAndGetThis<NapiJsContext>(env, info);
    CHECK_POINTER_AND_RETURN_LOG(object, CreateJsUndefined(env), "CheckParamsAndGetThis return nullptr");

    return object->OnGetBundleName(env, info);
}

napi_value NapiJsContext::JsVerifyPermission(napi_env env, napi_callback_info info)
{
    CHECK_POINTER_AND_RETURN_LOG(env, nullptr, "but input parameters engine is nullptr");
    CHECK_POINTER_AND_RETURN_LOG(info, nullptr, "but input parameters info is nullptr");

    auto object = CheckParamsAndGetThis<NapiJsContext>(env, info);
    CHECK_POINTER_AND_RETURN_LOG(object, CreateJsUndefined(env), "CheckParamsAndGetThis return nullptr");

    return object->OnVerifyPermission(env, info);
}

napi_value NapiJsContext::JsGetApplicationInfo(napi_env env, napi_callback_info info)
{
    CHECK_POINTER_AND_RETURN_LOG(env, nullptr, "but input parameters engine is nullptr");
    CHECK_POINTER_AND_RETURN_LOG(info, nullptr, "but input parameters info is nullptr");

    auto object = CheckParamsAndGetThis<NapiJsContext>(env, info);
    CHECK_POINTER_AND_RETURN_LOG(object, CreateJsUndefined(env), "CheckParamsAndGetThis return nullptr");

    return object->OnGetApplicationInfo(env, info);
}

napi_value NapiJsContext::JsGetProcessInfo(napi_env env, napi_callback_info info)
{
    CHECK_POINTER_AND_RETURN_LOG(env, nullptr, "but input parameters env is nullptr");
    CHECK_POINTER_AND_RETURN_LOG(info, nullptr, "but input parameters info is nullptr");

    auto object = CheckParamsAndGetThis<NapiJsContext>(env, info);
    CHECK_POINTER_AND_RETURN_LOG(object, CreateJsUndefined(env), "CheckParamsAndGetThis return nullptr");

    return object->OnGetProcessInfo(env, info);
}

napi_value NapiJsContext::JsGetElementName(napi_env env, napi_callback_info info)
{
    CHECK_POINTER_AND_RETURN_LOG(env, nullptr, "but input parameters env is nullptr");
    CHECK_POINTER_AND_RETURN_LOG(info, nullptr, "but input parameters info is nullptr");

    auto object = CheckParamsAndGetThis<NapiJsContext>(env, info);
    CHECK_POINTER_AND_RETURN_LOG(object, CreateJsUndefined(env), "CheckParamsAndGetThis return nullptr");

    return object->OnGetElementName(env, info);
}

napi_value NapiJsContext::JsGetProcessName(napi_env env, napi_callback_info info)
{
    CHECK_POINTER_AND_RETURN_LOG(env, nullptr, "but input parameters env is nullptr");
    CHECK_POINTER_AND_RETURN_LOG(info, nullptr, "but input parameters info is nullptr");

    auto object = CheckParamsAndGetThis<NapiJsContext>(env, info);
    CHECK_POINTER_AND_RETURN_LOG(object, CreateJsUndefined(env), "CheckParamsAndGetThis return nullptr");

    return object->OnGetProcessName(env, info);
}

napi_value NapiJsContext::JsGetCallingBundle(napi_env env, napi_callback_info info)
{
    CHECK_POINTER_AND_RETURN_LOG(env, nullptr, "but input parameters env is nullptr");
    CHECK_POINTER_AND_RETURN_LOG(info, nullptr, "but input parameters info is nullptr");

    auto object = CheckParamsAndGetThis<NapiJsContext>(env, info);
    CHECK_POINTER_AND_RETURN_LOG(object, CreateJsUndefined(env), "CheckParamsAndGetThis return nullptr");

    return object->OnGetCallingBundle(env, info);
}

napi_value NapiJsContext::JsGetOrCreateLocalDir(napi_env env, napi_callback_info info)
{
    CHECK_POINTER_AND_RETURN_LOG(env, nullptr, "but input parameters env is nullptr");
    CHECK_POINTER_AND_RETURN_LOG(info, nullptr, "but input parameters info is nullptr");

    auto object = CheckParamsAndGetThis<NapiJsContext>(env, info);
    CHECK_POINTER_AND_RETURN_LOG(object, CreateJsUndefined(env), "CheckParamsAndGetThis return nullptr");

    return object->OnGetOrCreateLocalDir(env, info);
}

napi_value NapiJsContext::JsGetFilesDir(napi_env env, napi_callback_info info)
{
    CHECK_POINTER_AND_RETURN_LOG(env, nullptr, "but input parameters env is nullptr");
    CHECK_POINTER_AND_RETURN_LOG(info, nullptr, "but input parameters info is nullptr");

    auto object = CheckParamsAndGetThis<NapiJsContext>(env, info);
    CHECK_POINTER_AND_RETURN_LOG(object, CreateJsUndefined(env), "CheckParamsAndGetThis return nullptr");

    return object->JsNapiCommon::JsGetFilesDir(env, info, AbilityType::PAGE);
}

napi_value NapiJsContext::JsIsUpdatingConfigurations(napi_env env, napi_callback_info info)
{
    CHECK_POINTER_AND_RETURN_LOG(env, nullptr, "but input parameters env is nullptr");
    CHECK_POINTER_AND_RETURN_LOG(info, nullptr, "but input parameters info is nullptr");

    auto object = CheckParamsAndGetThis<NapiJsContext>(env, info);
    CHECK_POINTER_AND_RETURN_LOG(object, CreateJsUndefined(env), "CheckParamsAndGetThis return nullptr");

    return object->JsNapiCommon::JsIsUpdatingConfigurations(env, info, AbilityType::PAGE);
}

napi_value NapiJsContext::JsPrintDrawnCompleted(napi_env env, napi_callback_info info)
{
    CHECK_POINTER_AND_RETURN_LOG(env, nullptr, "but input parameters env is nullptr");
    CHECK_POINTER_AND_RETURN_LOG(info, nullptr, "but input parameters info is nullptr");

    auto object = CheckParamsAndGetThis<NapiJsContext>(env, info);
    CHECK_POINTER_AND_RETURN_LOG(object, CreateJsUndefined(env), "CheckParamsAndGetThis return nullptr");

    return object->JsNapiCommon::JsPrintDrawnCompleted(env, info, AbilityType::PAGE);
}

napi_value NapiJsContext::JsGetCacheDir(napi_env env, napi_callback_info info)
{
    CHECK_POINTER_AND_RETURN_LOG(env, nullptr, "but input parameters env is nullptr");
    CHECK_POINTER_AND_RETURN_LOG(info, nullptr, "but input parameters info is nullptr");

    auto object = CheckParamsAndGetThis<NapiJsContext>(env, info);
    CHECK_POINTER_AND_RETURN_LOG(object, CreateJsUndefined(env), "CheckParamsAndGetThis return nullptr");

    return object->JsNapiCommon::JsGetCacheDir(env, info, AbilityType::PAGE);
}

napi_value NapiJsContext::JsGetCtxAppType(napi_env env, napi_callback_info info)
{
    CHECK_POINTER_AND_RETURN_LOG(env, nullptr, "but input parameters env is nullptr");
    CHECK_POINTER_AND_RETURN_LOG(info, nullptr, "but input parameters info is nullptr");

    auto object = CheckParamsAndGetThis<NapiJsContext>(env, info);
    CHECK_POINTER_AND_RETURN_LOG(object, CreateJsUndefined(env), "CheckParamsAndGetThis return nullptr");

    return object->JsNapiCommon::JsGetCtxAppType(env, info, AbilityType::PAGE);
}

napi_value NapiJsContext::JsGetCtxHapModuleInfo(napi_env env, napi_callback_info info)
{
    CHECK_POINTER_AND_RETURN_LOG(env, nullptr, "but input parameters env is nullptr");
    CHECK_POINTER_AND_RETURN_LOG(info, nullptr, "but input parameters info is nullptr");

    auto object = CheckParamsAndGetThis<NapiJsContext>(env, info);
    CHECK_POINTER_AND_RETURN_LOG(object, CreateJsUndefined(env), "CheckParamsAndGetThis return nullptr");

    return object->JsNapiCommon::JsGetCtxHapModuleInfo(env, info, AbilityType::PAGE);
}

napi_value NapiJsContext::JsGetAppVersionInfo(napi_env env, napi_callback_info info)
{
    CHECK_POINTER_AND_RETURN_LOG(env, nullptr, "but input parameters env is nullptr");
    CHECK_POINTER_AND_RETURN_LOG(info, nullptr, "but input parameters info is nullptr");

    auto object = CheckParamsAndGetThis<NapiJsContext>(env, info);
    CHECK_POINTER_AND_RETURN_LOG(object, CreateJsUndefined(env), "CheckParamsAndGetThis return nullptr");

    return object->JsNapiCommon::JsGetAppVersionInfo(env, info, AbilityType::PAGE);
}

napi_value NapiJsContext::JsGetApplicationContext(napi_env env, napi_callback_info info)
{
    CHECK_POINTER_AND_RETURN_LOG(env, nullptr, "but input parameters env is nullptr");
    CHECK_POINTER_AND_RETURN_LOG(info, nullptr, "but input parameters info is nullptr");

    auto object = CheckParamsAndGetThis<NapiJsContext>(env, info);
    CHECK_POINTER_AND_RETURN_LOG(object, CreateJsUndefined(env), "CheckParamsAndGetThis return nullptr");

    return object->JsNapiCommon::JsGetContext(env, info, AbilityType::PAGE);
}

napi_value NapiJsContext::JsGetCtxAbilityInfo(napi_env env, napi_callback_info info)
{
    CHECK_POINTER_AND_RETURN_LOG(env, nullptr, "but input parameters env is nullptr");
    CHECK_POINTER_AND_RETURN_LOG(info, nullptr, "but input parameters info is nullptr");

    auto object = CheckParamsAndGetThis<NapiJsContext>(env, info);
    CHECK_POINTER_AND_RETURN_LOG(object, CreateJsUndefined(env), "CheckParamsAndGetThis return nullptr");

    return object->JsNapiCommon::JsGetCtxAbilityInfo(env, info, AbilityType::PAGE);
}

napi_value NapiJsContext::JsSetShowOnLockScreen(napi_env env, napi_callback_info info)
{
#ifdef SUPPORT_GRAPHICS
    CHECK_POINTER_AND_RETURN_LOG(env, nullptr, "but input parameters env is nullptr");
    CHECK_POINTER_AND_RETURN_LOG(info, nullptr, "but input parameters info is nullptr");

    auto object = CheckParamsAndGetThis<NapiJsContext>(env, info);
    CHECK_POINTER_AND_RETURN_LOG(object, CreateJsUndefined(env), "CheckParamsAndGetThis return nullptr");

    return object->OnSetShowOnLockScreen(env, info);
#else
   return nullptr;
#endif
}

napi_value NapiJsContext::JsGetOrCreateDistributedDir(napi_env env, napi_callback_info info)
{
    CHECK_POINTER_AND_RETURN_LOG(env, nullptr, "but input parameters env is nullptr");
    CHECK_POINTER_AND_RETURN_LOG(info, nullptr, "but input parameters info is nullptr");

    auto object = CheckParamsAndGetThis<NapiJsContext>(env, info);
    CHECK_POINTER_AND_RETURN_LOG(object, CreateJsUndefined(env), "CheckParamsAndGetThis return nullptr");

    return object->JsNapiCommon::JsGetOrCreateDistributedDir(env, info, AbilityType::PAGE);
}

napi_value NapiJsContext::JsSetWakeUpScreen(napi_env env, napi_callback_info info)
{
#ifdef SUPPORT_GRAPHICS
    CHECK_POINTER_AND_RETURN_LOG(env, nullptr, "but input parameters env is nullptr");
    CHECK_POINTER_AND_RETURN_LOG(info, nullptr, "but input parameters info is nullptr");

    auto object = CheckParamsAndGetThis<NapiJsContext>(env, info);
    CHECK_POINTER_AND_RETURN_LOG(object, CreateJsUndefined(env), "CheckParamsAndGetThis return nullptr");

    return object->OnSetWakeUpScreen(env, info);
#else
   return nullptr;
#endif
}

napi_value NapiJsContext::JsSetDisplayOrientation(napi_env env, napi_callback_info info)
{
#ifdef SUPPORT_GRAPHICS
    CHECK_POINTER_AND_RETURN_LOG(env, nullptr, "but input parameters env is nullptr");
    CHECK_POINTER_AND_RETURN_LOG(info, nullptr, "but input parameters info is nullptr");

    auto object = CheckParamsAndGetThis<NapiJsContext>(env, info);
    CHECK_POINTER_AND_RETURN_LOG(object, CreateJsUndefined(env), "CheckParamsAndGetThis return nullptr");

    return object->OnSetDisplayOrientation(env, info);
#else
   return nullptr;
#endif
}

napi_value NapiJsContext::JsGetDisplayOrientation(napi_env env, napi_callback_info info)
{
#ifdef SUPPORT_GRAPHICS
    CHECK_POINTER_AND_RETURN_LOG(env, nullptr, "but input parameters env is nullptr");
    CHECK_POINTER_AND_RETURN_LOG(info, nullptr, "but input parameters info is nullptr");

    auto object = CheckParamsAndGetThis<NapiJsContext>(env, info);
    CHECK_POINTER_AND_RETURN_LOG(object, CreateJsUndefined(env), "CheckParamsAndGetThis return nullptr");

    return object->JsNapiCommon::JsGetDisplayOrientation(env, info, AbilityType::PAGE);
#else
   return nullptr;
#endif
}

napi_value NapiJsContext::JsGetExternalCacheDir(napi_env env, napi_callback_info info)
{
    CHECK_POINTER_AND_RETURN_LOG(env, nullptr, "but input parameters env is nullptr");
    CHECK_POINTER_AND_RETURN_LOG(info, nullptr, "but input parameters info is nullptr");

    auto object = CheckParamsAndGetThis<NapiJsContext>(env, info);
    CHECK_POINTER_AND_RETURN_LOG(object, CreateJsUndefined(env), "CheckParamsAndGetThis return nullptr");

    return object->JsNapiCommon::JsGetExternalCacheDir(env, info, AbilityType::PAGE);
}

bool NapiJsContext::DataInit(napi_env env)
{
    TAG_LOGD(AAFwkTag::JSNAPI, "called");
    napi_value global = nullptr;
    napi_value abilityObj = nullptr;
    TAG_LOGI(AAFwkTag::JSNAPI, "Get Ability to start");
    NAPI_CALL_BASE(env, napi_get_global(env, &global), false);
    NAPI_CALL_BASE(env, napi_get_named_property(env, global, "ability", &abilityObj), false);
    napi_status status = napi_get_value_external(env, abilityObj, reinterpret_cast<void **>(&ability_));
    if (status != napi_ok) {
        TAG_LOGW(AAFwkTag::JSNAPI, "Failed to get external ability info");
    }
    TAG_LOGD(AAFwkTag::JSNAPI, "end");

    return true;
}

napi_value NapiJsContext::OnRequestPermissionsFromUser(napi_env env, napi_callback_info info)
{
    TAG_LOGD(AAFwkTag::JSNAPI, "called");
    size_t argc = ARGS_MAX_COUNT;
    napi_value argv[ARGS_MAX_COUNT] = {nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc == ARGS_ZERO || argc > ARGS_THREE) {
        TAG_LOGE(AAFwkTag::JSNAPI, "input params count error, argc=%{public}zu", argc);
        return CreateJsUndefined(env);
    }
    CallAbilityPermissionParam permissionParam;
    if (!GetStringsValue(env, argv[PARAM0], permissionParam.permission_list)) {
        TAG_LOGE(AAFwkTag::JSNAPI, "input params string error");
        return CreateJsUndefined(env);
    }

    if (!ConvertFromJsValue(env, argv[PARAM1], permissionParam.requestCode)) {
        TAG_LOGE(AAFwkTag::JSNAPI, "input params int error");
        return CreateJsUndefined(env);
    }

    auto callback = argc == ARGS_THREE ? argv[PARAM2] : nullptr;
    napi_value result = nullptr;
    auto napiAsyncTask =
        AbilityRuntime::CreateAsyncTaskWithLastParam(env, callback, nullptr, nullptr, &result).release();

    int32_t errorCode = NAPI_ERR_NO_ERROR;
    if (ability_ == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null ability");
        errorCode = NAPI_ERR_ACE_ABILITY;
    }

    if (permissionParam.permission_list.size() == 0) {
        TAG_LOGE(AAFwkTag::JSNAPI, "permission_list size is 0");
        errorCode = NAPI_ERR_PARAM_INVALID;
    }

    if (errorCode != NAPI_ERR_NO_ERROR) {
        napi_value errorValue = CreateJsError(env, errorCode, ConvertErrorCode(errorCode));
        napiAsyncTask->Reject(env, errorValue);
        delete napiAsyncTask;
        napiAsyncTask = nullptr;
    } else {
        CallbackInfo callbackInfo;
        callbackInfo.env = env;
        callbackInfo.napiAsyncTask = napiAsyncTask;
        AbilityProcess::GetInstance()->RequestPermissionsFromUser(ability_, permissionParam, callbackInfo);
    }

    return result;
}

napi_value NapiJsContext::OnGetBundleName(napi_env env, napi_callback_info info)
{
    TAG_LOGD(AAFwkTag::JSNAPI, "called");
    size_t argc = ARGS_MAX_COUNT;
    napi_value argv[ARGS_MAX_COUNT] = {nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc > ARGS_ONE) {
        TAG_LOGE(AAFwkTag::JSNAPI, "input params count error, argc=%{public}zu", argc);
        return CreateJsNull(env);
    }

    auto errorVal = std::make_shared<int32_t>(static_cast<int32_t>(NAPI_ERR_NO_ERROR));
    std::shared_ptr<JsBundleName> bundleName = std::make_shared<JsBundleName>();
    auto execute = [obj = this, name = bundleName, value = errorVal] () {
        if (obj->ability_ == nullptr) {
            *value = static_cast<int32_t>(NAPI_ERR_ACE_ABILITY);
            TAG_LOGE(AAFwkTag::JSNAPI, "null ability");
            return;
        }
        if (name == nullptr) {
            *value = static_cast<int32_t>(NAPI_ERR_ABILITY_CALL_INVALID);
            TAG_LOGE(AAFwkTag::JSNAPI, "null name");
            return;
        }
        name->name = obj->ability_->GetBundleName();
    };
    auto complete = [obj = this, name = bundleName, value = errorVal]
        (napi_env env, NapiAsyncTask &task, int32_t status) {
        if (*value != static_cast<int32_t>(NAPI_ERR_NO_ERROR) || name == nullptr) {
            auto ecode = name == nullptr ? static_cast<int32_t>(NAPI_ERR_ABILITY_CALL_INVALID) : *value;
            task.Reject(env, CreateJsError(env, ecode, obj->ConvertErrorCode(ecode)));
            TAG_LOGD(AAFwkTag::JSNAPI, "task execute error, name is nullptr or NAPI_ERR_ABILITY_CALL_INVALID");
            return;
        }
        task.Resolve(env, CreateJsValue(env, name->name));
    };

    auto callback = argc == ARGS_ZERO ? nullptr : argv[PARAM0];
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleHighQos("NapiJsContext::OnGetBundleName",
        env, CreateAsyncTaskWithLastParam(env, callback, std::move(execute), std::move(complete), &result));

    return result;
}

napi_value NapiJsContext::OnVerifyPermission(napi_env env, napi_callback_info info)
{
    TAG_LOGD(AAFwkTag::JSNAPI, "called");
    size_t argc = ARGS_MAX_COUNT;
    napi_value argv[ARGS_MAX_COUNT] = {nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc == ARGS_ZERO || argc > ARGS_THREE) {
        TAG_LOGE(AAFwkTag::JSNAPI, "input params count error, argc=%{public}zu", argc);
        return CreateJsNull(env);
    }

    auto errorVal = std::make_shared<int32_t>(static_cast<int32_t>(NAPI_ERR_NO_ERROR));
    std::string permission("");
    if (!ConvertFromJsValue(env, argv[PARAM0], permission)) {
        TAG_LOGE(AAFwkTag::JSNAPI, "input params string error");
        return CreateJsNull(env);
    }
    JsPermissionOptions options;
    bool flagCall = UnwrapVerifyPermissionParams(env, info, options);
    auto execute = [obj = this, permission, options, value = errorVal] () {
        if (obj->ability_ == nullptr) {
            *value = static_cast<int32_t>(NAPI_ERR_ACE_ABILITY);
            TAG_LOGE(AAFwkTag::JSNAPI, "null ability");
            return;
        }
        if (options.uidFlag) {
            *value = obj->ability_->VerifyPermission(permission, options.pid, options.uid);
        } else {
            *value = obj->ability_->VerifySelfPermission(permission);
        }
    };
    auto complete = [obj = this, value = errorVal] (napi_env env, NapiAsyncTask &task, int32_t status) {
        if (*value == static_cast<int32_t>(NAPI_ERR_ACE_ABILITY)) {
            task.Reject(env, CreateJsError(env, *value, obj->ConvertErrorCode(*value)));
            return;
        }
        task.Resolve(env, CreateJsValue(env, *value));
    };

    auto callback = flagCall ? ((argc == ARGS_TWO) ? argv[PARAM1] : argv[PARAM2]) : nullptr;
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleHighQos("NapiJsContext::OnGetBundleName",
        env, CreateAsyncTaskWithLastParam(env, callback, std::move(execute), std::move(complete), &result));

    return result;
}

napi_value NapiJsContext::OnGetApplicationInfo(napi_env env, napi_callback_info info)
{
    TAG_LOGD(AAFwkTag::JSNAPI, "called");
    size_t argc = ARGS_MAX_COUNT;
    napi_value argv[ARGS_MAX_COUNT] = {nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc > ARGS_ONE) {
        TAG_LOGE(AAFwkTag::JSNAPI, "input params count error, argc=%{public}zu", argc);
        return CreateJsUndefined(env);
    }

    auto errorVal = std::make_shared<int32_t>(static_cast<int32_t>(NAPI_ERR_NO_ERROR));
    std::shared_ptr<JsApplicationInfo> infoData = std::make_shared<JsApplicationInfo>();
    auto execute = [obj = this, info = infoData, value = errorVal] () {
        if (obj->ability_ == nullptr) {
            *value = static_cast<int32_t>(NAPI_ERR_ACE_ABILITY);
            TAG_LOGE(AAFwkTag::JSNAPI, "null ability");
            return;
        }
        auto getInfo = obj->ability_->GetApplicationInfo();
        if (getInfo != nullptr && info != nullptr) {
            info->appInfo = *getInfo;
        } else {
            TAG_LOGE(AAFwkTag::JSNAPI, "GetApplicationInfo return nullptr");
            *value = static_cast<int32_t>(NAPI_ERR_ABILITY_CALL_INVALID);
        }
    };
    auto complete = [obj = this, info = infoData, value = errorVal]
        (napi_env env, NapiAsyncTask &task, int32_t status) {
        if (*value != static_cast<int32_t>(NAPI_ERR_NO_ERROR) || info == nullptr) {
            TAG_LOGD(AAFwkTag::JSNAPI, "errorVal is 0 or JsHapModuleInfo is null");
            auto ecode = info == nullptr ? static_cast<int32_t>(NAPI_ERR_ABILITY_CALL_INVALID) : *value;
            task.Reject(env, CreateJsError(env, ecode, obj->ConvertErrorCode(ecode)));
            return;
        }
        task.Resolve(env, obj->CreateAppInfo(env, info->appInfo));
    };

    auto callback = argc == ARGS_ZERO ? nullptr : argv[PARAM0];
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleHighQos("NapiJsContext::OnGetApplicationInfo",
        env, CreateAsyncTaskWithLastParam(env, callback, std::move(execute), std::move(complete), &result));

    return result;
}

napi_value NapiJsContext::OnGetProcessInfo(napi_env env, napi_callback_info info)
{
    TAG_LOGD(AAFwkTag::JSNAPI, "called");
    size_t argc = ARGS_MAX_COUNT;
    napi_value argv[ARGS_MAX_COUNT] = {nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc > ARGS_ONE) {
        TAG_LOGE(AAFwkTag::JSNAPI, "input params count error, argc=%{public}zu", argc);
        return CreateJsUndefined(env);
    }

    auto errorVal = std::make_shared<int32_t>(static_cast<int32_t>(NAPI_ERR_NO_ERROR));
    std::shared_ptr<JsProcessInfo> processInfo = std::make_shared<JsProcessInfo>();
    auto execute = [obj = this, data = processInfo, value = errorVal] () {
        if (obj->ability_ == nullptr) {
            *value = static_cast<int32_t>(NAPI_ERR_ACE_ABILITY);
            TAG_LOGE(AAFwkTag::JSNAPI, "null ability");
            return;
        }
        auto getInfo = obj->ability_->GetProcessInfo();
        if (getInfo != nullptr && data != nullptr) {
            data->processName = getInfo->GetProcessName();
            data->pid = getInfo->GetPid();
        } else {
            TAG_LOGE(AAFwkTag::JSNAPI, "GetProcessInfo return nullptr");
            *value = static_cast<int32_t>(NAPI_ERR_ABILITY_CALL_INVALID);
        }
    };
    auto complete = [obj = this, info = processInfo, value = errorVal]
        (napi_env env, NapiAsyncTask &task, int32_t status) {
        if (*value != static_cast<int32_t>(NAPI_ERR_NO_ERROR) || info == nullptr) {
            auto ecode = info == nullptr ? (NAPI_ERR_ABILITY_CALL_INVALID) : *value;
            task.Reject(env, CreateJsError(env, ecode, obj->ConvertErrorCode(ecode)));
            return;
        }
        task.Resolve(env, obj->CreateProcessInfo(env, info));
    };

    auto callback = argc == ARGS_ZERO ? nullptr : argv[PARAM0];
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleHighQos("NapiJsContext::OnGetProcessInfo",
        env, CreateAsyncTaskWithLastParam(env, callback, std::move(execute), std::move(complete), &result));

    return result;
}

napi_value NapiJsContext::OnGetElementName(napi_env env, napi_callback_info info)
{
    TAG_LOGD(AAFwkTag::JSNAPI, "called");
    size_t argc = ARGS_MAX_COUNT;
    napi_value argv[ARGS_MAX_COUNT] = {nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc > ARGS_ONE) {
        TAG_LOGE(AAFwkTag::JSNAPI, "input params count error, argc=%{public}zu", argc);
        return CreateJsUndefined(env);
    }

    auto errorVal = std::make_shared<int32_t>(static_cast<int32_t>(NAPI_ERR_NO_ERROR));
    std::shared_ptr<JsElementName> elementName = std::make_shared<JsElementName>();
    auto execute = [obj = this, data = elementName, value = errorVal] () {
        if (obj->ability_ == nullptr) {
            *value = static_cast<int32_t>(NAPI_ERR_ACE_ABILITY);
            TAG_LOGE(AAFwkTag::JSNAPI, "null ability");
            return;
        }
        auto elementName = obj->ability_->GetElementName();
        if (elementName != nullptr && data != nullptr) {
            data->deviceId = elementName->GetDeviceID();
            data->bundleName = elementName->GetBundleName();
            data->abilityName = elementName->GetAbilityName();
            data->uri = obj->ability_->GetWant()->GetUriString();
            data->shortName = "";
        } else {
            TAG_LOGE(AAFwkTag::JSNAPI, "GetElementName return nullptr");
            *value = static_cast<int32_t>(NAPI_ERR_ABILITY_CALL_INVALID);
        }
    };
    auto complete = [obj = this, ename = elementName, value = errorVal]
        (napi_env env, NapiAsyncTask &task, int32_t status) {
        if (*value != static_cast<int32_t>(NAPI_ERR_NO_ERROR) || ename == nullptr) {
            auto ecode = ename == nullptr ? static_cast<int32_t>(NAPI_ERR_ABILITY_CALL_INVALID) : *value;
            task.Reject(env, CreateJsError(env, ecode, obj->ConvertErrorCode(ecode)));
            return;
        }
        task.Resolve(env, obj->CreateElementName(env, ename));
    };

    auto callback = argc == ARGS_ZERO ? nullptr : argv[PARAM0];
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleHighQos("NapiJsContext::OnGetElementName",
        env, CreateAsyncTaskWithLastParam(env, callback, std::move(execute), std::move(complete), &result));

    return result;
}

napi_value NapiJsContext::OnGetProcessName(napi_env env, napi_callback_info info)
{
    TAG_LOGD(AAFwkTag::JSNAPI, "called");
    size_t argc = ARGS_MAX_COUNT;
    napi_value argv[ARGS_MAX_COUNT] = {nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc > ARGS_ONE) {
        TAG_LOGE(AAFwkTag::JSNAPI, "input params count error, argc=%{public}zu", argc);
        return CreateJsUndefined(env);
    }

    auto errorVal = std::make_shared<int32_t>(static_cast<int32_t>(NAPI_ERR_NO_ERROR));
    std::shared_ptr<JsProcessName> processName = std::make_shared<JsProcessName>();
    auto execute = [obj = this, name = processName, value = errorVal] () {
        if (obj->ability_ == nullptr) {
            *value = static_cast<int32_t>(NAPI_ERR_ACE_ABILITY);
            TAG_LOGE(AAFwkTag::JSNAPI, "null ability");
            return;
        }
        if (name == nullptr) {
            *value = static_cast<int32_t>(NAPI_ERR_ABILITY_CALL_INVALID);
            TAG_LOGE(AAFwkTag::JSNAPI, "null name");
            return;
        }
        name->name = obj->ability_->GetProcessName();
    };
    auto complete = [obj = this, name = processName, value = errorVal]
        (napi_env env, NapiAsyncTask &task, int32_t status) {
        if (*value != static_cast<int32_t>(NAPI_ERR_NO_ERROR) || name == nullptr) {
            auto ecode = name == nullptr ? static_cast<int32_t>(NAPI_ERR_ABILITY_CALL_INVALID) : *value;
            task.Reject(env, CreateJsError(env, ecode, obj->ConvertErrorCode(ecode)));
            TAG_LOGD(AAFwkTag::JSNAPI, "task execute error, name is nullptr or NAPI_ERR_ABILITY_CALL_INVALID");
            return;
        }
        task.Resolve(env, CreateJsValue(env, name->name));
    };

    auto callback = argc == ARGS_ZERO ? nullptr : argv[PARAM0];
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleHighQos("NapiJsContext::OnGetProcessName",
        env, CreateAsyncTaskWithLastParam(env, callback, std::move(execute), std::move(complete), &result));

    return result;
}

napi_value NapiJsContext::OnGetCallingBundle(napi_env env, napi_callback_info info)
{
    TAG_LOGD(AAFwkTag::JSNAPI, "called");
    size_t argc = ARGS_MAX_COUNT;
    napi_value argv[ARGS_MAX_COUNT] = {nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc > ARGS_ONE) {
        TAG_LOGE(AAFwkTag::JSNAPI, "input params count error, argc=%{public}zu", argc);
        return CreateJsUndefined(env);
    }

    auto errorVal = std::make_shared<int32_t>(static_cast<int32_t>(NAPI_ERR_NO_ERROR));
    std::shared_ptr<JsCallingBundleName> callingBundleName = std::make_shared<JsCallingBundleName>();
    auto execute = [obj = this, name = callingBundleName, value = errorVal] () {
        if (obj->ability_ == nullptr) {
            *value = static_cast<int32_t>(NAPI_ERR_ACE_ABILITY);
            TAG_LOGE(AAFwkTag::JSNAPI, "null ability");
            return;
        }
        if (name == nullptr) {
            *value = static_cast<int32_t>(NAPI_ERR_ABILITY_CALL_INVALID);
            TAG_LOGE(AAFwkTag::JSNAPI, "null name");
            return;
        }
        name->name = obj->ability_->GetCallingBundle();
    };
    auto complete = [obj = this, name = callingBundleName, value = errorVal]
        (napi_env env, NapiAsyncTask &task, int32_t status) {
        if (*value != static_cast<int32_t>(NAPI_ERR_NO_ERROR) || name == nullptr) {
            auto ecode = name == nullptr ? static_cast<int32_t>(NAPI_ERR_ABILITY_CALL_INVALID) : *value;
            task.Reject(env, CreateJsError(env, ecode, obj->ConvertErrorCode(ecode)));
            return;
        }
        task.Resolve(env, CreateJsValue(env, name->name));
    };

    auto callback = argc == ARGS_ZERO ? nullptr : argv[PARAM0];
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleHighQos("NapiJsContext::OnGetCallingBundle",
        env, CreateAsyncTaskWithLastParam(env, callback, std::move(execute), std::move(complete), &result));

    return result;
}

napi_value NapiJsContext::OnGetOrCreateLocalDir(napi_env env, napi_callback_info info)
{
    TAG_LOGD(AAFwkTag::JSNAPI, "called");
    size_t argc = ARGS_MAX_COUNT;
    napi_value argv[ARGS_MAX_COUNT] = {nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc > ARGS_ONE) {
        TAG_LOGE(AAFwkTag::JSNAPI, "input params count error, argc=%{public}zu", argc);
        return CreateJsUndefined(env);
    }

    auto errorVal = std::make_shared<int32_t>(static_cast<int32_t>(NAPI_ERR_NO_ERROR));
    std::shared_ptr<JsOrCreateLocalDir> createDir = std::make_shared<JsOrCreateLocalDir>();
    auto execute = [obj = this, dir = createDir, value = errorVal] () {
        if (obj->ability_ == nullptr) {
            *value = static_cast<int32_t>(NAPI_ERR_ACE_ABILITY);
            TAG_LOGE(AAFwkTag::JSNAPI, "null ability");
            return;
        }
        auto context = obj->ability_->GetAbilityContext();
        if (context == nullptr || dir == nullptr) {
            *value = static_cast<int32_t>(NAPI_ERR_ABILITY_CALL_INVALID);
            TAG_LOGE(AAFwkTag::JSNAPI, "null context or dir");
            return;
        }
        dir->name = context->GetBaseDir();
        if (!OHOS::FileExists(dir->name)) {
            TAG_LOGI(AAFwkTag::JSNAPI, "create dir");
            OHOS::ForceCreateDirectory(dir->name);
            OHOS::ChangeModeDirectory(dir->name, MODE);
        }
    };
    auto complete = [obj = this, dir = createDir, value = errorVal]
        (napi_env env, NapiAsyncTask &task, int32_t status) {
        if (*value != static_cast<int32_t>(NAPI_ERR_NO_ERROR) || dir == nullptr) {
            TAG_LOGD(AAFwkTag::JSNAPI, "errorVal is error or JsCacheDir is nullptr");
            auto ecode = dir == nullptr ? static_cast<int32_t>(NAPI_ERR_ABILITY_CALL_INVALID) : *value;
            task.Reject(env, CreateJsError(env, ecode, obj->ConvertErrorCode(ecode)));
            return;
        }
        task.Resolve(env, CreateJsValue(env, dir->name));
    };
    auto callback = argc == ARGS_ZERO ? nullptr : argv[PARAM0];
    napi_value result = nullptr;
    NapiAsyncTask::Schedule("NapiJsContext::OnGetOrCreateLocalDir",
        env, CreateAsyncTaskWithLastParam(env, callback, std::move(execute), std::move(complete), &result));

    return result;
}

napi_value NapiJsContext::OnSetShowOnLockScreen(napi_env env, napi_callback_info info)
{
    TAG_LOGD(AAFwkTag::JSNAPI, "called");
    size_t argc = ARGS_MAX_COUNT;
    napi_value argv[ARGS_MAX_COUNT] = {nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc == ARGS_ZERO || argc > ARGS_TWO) {
        TAG_LOGE(AAFwkTag::JSNAPI, "input params count error, argc=%{public}zu", argc);
        return CreateJsUndefined(env);
    }

    auto errorVal = std::make_shared<int32_t>(static_cast<int32_t>(NAPI_ERR_NO_ERROR));
    bool isShow = false;
    if (!ConvertFromJsValue(env, argv[PARAM0], isShow)) {
        TAG_LOGE(AAFwkTag::JSNAPI, "input params int error");
        return CreateJsUndefined(env);
    }
    auto complete = [obj = this, isShow, value = errorVal]
        (napi_env env, NapiAsyncTask &task, int32_t status) {
        if (obj->ability_ == nullptr) {
            task.Reject(env, CreateJsError(env, static_cast<int32_t>(NAPI_ERR_ACE_ABILITY), "get ability error"));
            return;
        }
#ifdef SUPPORT_SCREEN
        obj->ability_->SetShowOnLockScreen(isShow);
#endif
        task.Resolve(env, CreateJsUndefined(env));
    };

    auto callback = argc == ARGS_ONE ? nullptr : argv[PARAM1];
    napi_value result = nullptr;
    NapiAsyncTask::Schedule("NapiJsContext::OnSetShowOnLockScreen",
        env, CreateAsyncTaskWithLastParam(env, callback, nullptr, std::move(complete), &result));

    return result;
}

napi_value NapiJsContext::OnSetWakeUpScreen(napi_env env, napi_callback_info info)
{
    TAG_LOGD(AAFwkTag::JSNAPI, "called");
    size_t argc = ARGS_MAX_COUNT;
    napi_value argv[ARGS_MAX_COUNT] = {nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc == ARGS_ZERO || argc > ARGS_TWO) {
        TAG_LOGE(AAFwkTag::JSNAPI, "input params count error, argc=%{public}zu", argc);
        return CreateJsUndefined(env);
    }

    bool wakeUp = false;
    if (!ConvertFromJsValue(env, argv[PARAM0], wakeUp)) {
        TAG_LOGE(AAFwkTag::JSNAPI, "input params int error");
        return CreateJsUndefined(env);
    }
    auto complete = [obj = this, wakeUp]
        (napi_env env, NapiAsyncTask &task, int32_t status) {
        if (obj->ability_ == nullptr) {
            task.Reject(env, CreateJsError(env, static_cast<int32_t>(NAPI_ERR_ACE_ABILITY), "get ability error"));
            return;
        }
#ifdef SUPPORT_SCREEN
        obj->ability_->SetWakeUpScreen(wakeUp);
#endif
        task.Resolve(env, CreateJsUndefined(env));
    };

    auto callback = argc == ARGS_ONE ? nullptr : argv[PARAM1];
    napi_value result = nullptr;
    NapiAsyncTask::Schedule("NapiJsContext::OnSetWakeUpScreen",
        env, CreateAsyncTaskWithLastParam(env, callback, nullptr, std::move(complete), &result));

    return result;
}

napi_value NapiJsContext::OnSetDisplayOrientation(napi_env env, napi_callback_info info)
{
    TAG_LOGD(AAFwkTag::JSNAPI, "called");
    size_t argc = ARGS_MAX_COUNT;
    napi_value argv[ARGS_MAX_COUNT] = {nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc == ARGS_ZERO || argc > ARGS_TWO) {
        TAG_LOGE(AAFwkTag::JSNAPI, "input params count error, argc=%{public}zu", argc);
        return CreateJsUndefined(env);
    }

    int32_t orientation = 0;
    if (!ConvertFromJsValue(env, argv[PARAM0], orientation)) {
        TAG_LOGE(AAFwkTag::JSNAPI, "input params int error");
        return CreateJsUndefined(env);
    }

    int32_t maxRange = 3;
    if (orientation < 0 || orientation > maxRange) {
        TAG_LOGE(AAFwkTag::JSNAPI, "wrong parameter orientation : %{public}d", orientation);
        return CreateJsNull(env);
    }
    auto complete = [obj = this, orientationData = orientation]
        (napi_env env, NapiAsyncTask &task, int32_t status) {
        if (obj->ability_ == nullptr) {
            task.Reject(env, CreateJsError(env, static_cast<int32_t>(NAPI_ERR_ACE_ABILITY), "get ability error"));
            return;
        }
#ifdef SUPPORT_SCREEN
        obj->ability_->SetDisplayOrientation(orientationData);
#endif
        task.Resolve(env, CreateJsUndefined(env));
    };

    auto callback = argc == ARGS_ONE ? nullptr : argv[PARAM1];
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleHighQos("NapiJsContext::SetDisplayOrientation",
        env, CreateAsyncTaskWithLastParam(env, callback, nullptr, std::move(complete), &result));

    return result;
}
}  // namespace AppExecFwk
}  // namespace OHOS
