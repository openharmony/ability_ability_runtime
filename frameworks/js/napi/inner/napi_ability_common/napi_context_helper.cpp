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

#include "napi_context_helper.h"

#include <cstring>
#include <uv.h>

#include "napi_common_ability.h"
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
const std::string NAPI_CONTEXT_FILE_SEPARATOR = std::string("/");
const std::string NAPI_CONTEXT_DATABASE = std::string("database");
const std::string NAPI_CONTEXT_PREFERENCES = std::string("preferences");

#ifdef SUPPORT_GRAPHICS
static Ability* GetJSAbilityObject(napi_env env)
{
    napi_value global = nullptr;
    NAPI_CALL(env, napi_get_global(env, &global));

    napi_value abilityObj = nullptr;
    NAPI_CALL(env, napi_get_named_property(env, global, "ability", &abilityObj));

    Ability *ability = nullptr;
    NAPI_CALL(env, napi_get_value_external(env, abilityObj, reinterpret_cast<void **>(&ability)));
    return ability;
}

void SetShowOnLockScreenAsyncCompleteCB(napi_env env, napi_status status, void *data)
{
    TAG_LOGD(AAFwkTag::JSNAPI, "called");
    ShowOnLockScreenCB *showOnLockScreenCB = static_cast<ShowOnLockScreenCB *>(data);
    if (showOnLockScreenCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null showOnLockScreenCB");
        return;
    }

    showOnLockScreenCB->cbBase.errCode = NAPI_ERR_NO_ERROR;
    if (showOnLockScreenCB->cbBase.ability == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null ability");
        showOnLockScreenCB->cbBase.errCode = NAPI_ERR_ACE_ABILITY;
    } else {
#ifdef SUPPORT_SCREEN
        showOnLockScreenCB->cbBase.ability->SetShowOnLockScreen(showOnLockScreenCB->isShow);
#endif
    }

    napi_value callback = nullptr, undefined = nullptr, callResult = nullptr;
    napi_value result[ARGS_TWO] = {nullptr};
    napi_get_undefined(env, &undefined);
    result[PARAM0] = GetCallbackErrorValue(env, showOnLockScreenCB->cbBase.errCode);
    napi_get_null(env, &result[PARAM1]);
    napi_get_reference_value(env, showOnLockScreenCB->cbBase.cbInfo.callback, &callback);
    napi_call_function(env, undefined, callback, ARGS_TWO, &result[PARAM0], &callResult);

    if (showOnLockScreenCB->cbBase.cbInfo.callback != nullptr) {
        napi_delete_reference(env, showOnLockScreenCB->cbBase.cbInfo.callback);
    }
    napi_delete_async_work(env, showOnLockScreenCB->cbBase.asyncWork);
    delete showOnLockScreenCB;
    showOnLockScreenCB = nullptr;
}

napi_value SetShowOnLockScreenAsync(napi_env env, napi_value *args, ShowOnLockScreenCB *showOnLockScreenCB)
{
    TAG_LOGD(AAFwkTag::JSNAPI, "called");
    if (showOnLockScreenCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null showOnLockScreenCB");
        return nullptr;
    }

    napi_valuetype valuetypeParam1 = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[PARAM1], &valuetypeParam1));
    if (valuetypeParam1 != napi_function) {
        TAG_LOGE(AAFwkTag::JSNAPI, "error type");
        return nullptr;
    }

    NAPI_CALL(env, napi_create_reference(env, args[PARAM1], 1, &showOnLockScreenCB->cbBase.cbInfo.callback));

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName,
            [](napi_env env, void *data) {
                TAG_LOGI(AAFwkTag::JSNAPI, "execute");
            },
            SetShowOnLockScreenAsyncCompleteCB,
            static_cast<void *>(showOnLockScreenCB),
            &showOnLockScreenCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, showOnLockScreenCB->cbBase.asyncWork, napi_qos_user_initiated));
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));

    return result;
}

napi_value SetShowOnLockScreenPromise(napi_env env, ShowOnLockScreenCB *cbData)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "promise");
    if (cbData == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null cbData");
        return nullptr;
    }
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);

    napi_deferred deferred;
    napi_value promise = nullptr;
    napi_create_promise(env, &deferred, &promise);
    cbData->cbBase.deferred = deferred;

    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            TAG_LOGI(AAFwkTag::JSNAPI, "execute");
        },
        [](napi_env env, napi_status status, void *data) {
            ShowOnLockScreenCB *showOnLockScreenCB = static_cast<ShowOnLockScreenCB *>(data);
            showOnLockScreenCB->cbBase.errCode = NO_ERROR;
            if (showOnLockScreenCB->cbBase.ability == nullptr) {
                TAG_LOGE(AAFwkTag::JSNAPI, "null ability");
                showOnLockScreenCB->cbBase.errCode = NAPI_ERR_ACE_ABILITY;
            } else {
#ifdef SUPPORT_SCREEN
                showOnLockScreenCB->cbBase.ability->SetShowOnLockScreen(showOnLockScreenCB->isShow);
#endif
            }

            napi_value result = GetCallbackErrorValue(env, showOnLockScreenCB->cbBase.errCode);
            if (showOnLockScreenCB->cbBase.errCode == NO_ERROR) {
                napi_resolve_deferred(env, showOnLockScreenCB->cbBase.deferred, result);
            } else {
                napi_reject_deferred(env, showOnLockScreenCB->cbBase.deferred, result);
            }

            napi_delete_async_work(env, showOnLockScreenCB->cbBase.asyncWork);
            delete showOnLockScreenCB;
            showOnLockScreenCB = nullptr;
            TAG_LOGI(AAFwkTag::JSNAPI, "complete end");
        },
        static_cast<void *>(cbData),
        &cbData->cbBase.asyncWork);
    napi_queue_async_work_with_qos(env, cbData->cbBase.asyncWork, napi_qos_user_initiated);
    TAG_LOGI(AAFwkTag::JSNAPI, "promise end");
    return promise;
}

static void SetWakeUpScreenAsyncCompleteCB(napi_env env, napi_status status, void *data)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    SetWakeUpScreenCB *setWakeUpScreenCB = static_cast<SetWakeUpScreenCB *>(data);
    if (setWakeUpScreenCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null setWakeUpScreenCB");
        return;
    }

    do {
        setWakeUpScreenCB->cbBase.errCode = NAPI_ERR_NO_ERROR;
        if (setWakeUpScreenCB->cbBase.ability == nullptr) {
            TAG_LOGE(AAFwkTag::JSNAPI, "null ability");
            setWakeUpScreenCB->cbBase.errCode = NAPI_ERR_ACE_ABILITY;
            break;
        }
#ifdef SUPPORT_SCREEN
        setWakeUpScreenCB->cbBase.ability->SetWakeUpScreen(setWakeUpScreenCB->wakeUp);
#endif
    } while (false);

    napi_value callback = nullptr;
    napi_value undefined = nullptr;
    napi_value callResult = nullptr;
    napi_value result[ARGS_TWO] = {nullptr};
    napi_get_undefined(env, &undefined);
    result[PARAM0] = GetCallbackErrorValue(env, setWakeUpScreenCB->cbBase.errCode);
    napi_get_null(env, &result[PARAM1]);
    napi_get_reference_value(env, setWakeUpScreenCB->cbBase.cbInfo.callback, &callback);
    napi_call_function(env, undefined, callback, ARGS_TWO, &result[PARAM0], &callResult);

    if (setWakeUpScreenCB->cbBase.cbInfo.callback != nullptr) {
        napi_delete_reference(env, setWakeUpScreenCB->cbBase.cbInfo.callback);
    }
    napi_delete_async_work(env, setWakeUpScreenCB->cbBase.asyncWork);
    delete setWakeUpScreenCB;
    setWakeUpScreenCB = nullptr;
}


static napi_value SetWakeUpScreenAsync(napi_env env, napi_value *args, SetWakeUpScreenCB *cbData)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    if (cbData == nullptr || args == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null param");
        return nullptr;
    }

    napi_valuetype valuetypeParam0 = napi_undefined;
    napi_valuetype valuetypeParam1 = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[PARAM0], &valuetypeParam0));
    NAPI_CALL(env, napi_typeof(env, args[PARAM1], &valuetypeParam1));
    if (valuetypeParam0 != napi_boolean || valuetypeParam1 != napi_function) {
        TAG_LOGE(AAFwkTag::JSNAPI, "error type");
        return nullptr;
    }
    NAPI_CALL(env, napi_create_reference(env, args[PARAM1], 1, &cbData->cbBase.cbInfo.callback));

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env,
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                TAG_LOGI(AAFwkTag::JSNAPI, "execute called");
            },
            SetWakeUpScreenAsyncCompleteCB,
            static_cast<void *>(cbData),
            &cbData->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, cbData->cbBase.asyncWork));
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    return result;
}

napi_value SetWakeUpScreenPromise(napi_env env, SetWakeUpScreenCB *cbData)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "promise");
    if (cbData == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null cbData");
        return nullptr;
    }
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_deferred deferred;
    napi_value promise = nullptr;
    napi_create_promise(env, &deferred, &promise);
    cbData->cbBase.deferred = deferred;

    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            TAG_LOGI(AAFwkTag::JSNAPI, "execute called");
        },
        [](napi_env env, napi_status status, void *data) {
            TAG_LOGI(AAFwkTag::JSNAPI, "complete called");
            SetWakeUpScreenCB *setWakeUpScreenCB = static_cast<SetWakeUpScreenCB *>(data);
            setWakeUpScreenCB->cbBase.errCode = NO_ERROR;
            if (setWakeUpScreenCB->cbBase.ability == nullptr) {
                TAG_LOGE(AAFwkTag::JSNAPI, "null ability");
                setWakeUpScreenCB->cbBase.errCode = NAPI_ERR_ACE_ABILITY;
            } else {
#ifdef SUPPORT_SCREEN
                setWakeUpScreenCB->cbBase.ability->SetWakeUpScreen(setWakeUpScreenCB->wakeUp);
#endif
            }
            napi_value result = GetCallbackErrorValue(env, setWakeUpScreenCB->cbBase.errCode);
            if (setWakeUpScreenCB->cbBase.errCode == NO_ERROR) {
                napi_resolve_deferred(env, setWakeUpScreenCB->cbBase.deferred, result);
            } else {
                napi_reject_deferred(env, setWakeUpScreenCB->cbBase.deferred, result);
            }

            napi_delete_async_work(env, setWakeUpScreenCB->cbBase.asyncWork);
            delete setWakeUpScreenCB;
            setWakeUpScreenCB = nullptr;
            TAG_LOGI(AAFwkTag::JSNAPI, "complete end");
        },
        static_cast<void *>(cbData),
        &cbData->cbBase.asyncWork);
    napi_queue_async_work(env, cbData->cbBase.asyncWork);
    return promise;
}

napi_value SetWakeUpScreenWrap(napi_env env, napi_callback_info info, SetWakeUpScreenCB *cbData)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    if (cbData == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null cbData");
        return nullptr;
    }

    size_t argcAsync = 2;
    const size_t argStdValue = 2;
    const size_t argPromise = 1;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};

    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, nullptr, nullptr));
    if (argcAsync != argStdValue && argcAsync != argPromise) {
        TAG_LOGE(AAFwkTag::JSNAPI, "invalid argc");
        return nullptr;
    }

    if (!UnwrapBoolFromJS2(env, args[PARAM0], cbData->wakeUp)) {
        TAG_LOGE(AAFwkTag::JSNAPI, "UnwrapBoolFromJS2(wakeUp) run error");
        return nullptr;
    }

    napi_value global = nullptr;
    NAPI_CALL(env, napi_get_global(env, &global));

    napi_value abilityObj = nullptr;
    NAPI_CALL(env, napi_get_named_property(env, global, "ability", &abilityObj));

    Ability *ability = nullptr;
    NAPI_CALL(env, napi_get_value_external(env, abilityObj, reinterpret_cast<void **>(&ability)));

    cbData->cbBase.ability = ability;
    napi_value ret = nullptr;
    if (argcAsync == argStdValue) {
        ret = SetWakeUpScreenAsync(env, args, cbData);
    } else {
        ret = SetWakeUpScreenPromise(env, cbData);
    }
    return ret;
}

bool UnwrapSetDisplayOrientation(napi_env env, size_t argc, napi_value *argv, AsyncJSCallbackInfo *asyncCallbackInfo)
{
    TAG_LOGD(AAFwkTag::JSNAPI, "called, argc=%{public}zu", argc);

    const size_t argcMax = 2;
    if (argc > argcMax || argc < argcMax - 1) {
        TAG_LOGE(AAFwkTag::JSNAPI, "invalid argc");
        return false;
    }

    if (argc == argcMax) {
        if (!CreateAsyncCallback(env, argv[PARAM1], asyncCallbackInfo)) {
            TAG_LOGE(AAFwkTag::JSNAPI, "argv[PARAM1] invalid");
            return false;
        }
    }

    int orientation = 0;
    if (!UnwrapInt32FromJS2(env, argv[PARAM0], orientation)) {
        TAG_LOGE(AAFwkTag::JSNAPI, "argv[PARAM0] invalid");
        return false;
    }

    int maxRange = 3;
    if (orientation < 0 || orientation > maxRange) {
        TAG_LOGE(AAFwkTag::JSNAPI, "wrong parameter range");
        return false;
    }

    asyncCallbackInfo->param.paramArgs.PutIntValue("orientation", orientation);
    return true;
}

void SetDisplayOrientationExecuteCallbackWork(napi_env env, void *data)
{
    TAG_LOGD(AAFwkTag::JSNAPI, "called");
    AsyncJSCallbackInfo *asyncCallbackInfo = static_cast<AsyncJSCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null asyncCallbackInfo");
        return;
    }

    asyncCallbackInfo->error_code = NAPI_ERR_NO_ERROR;
    asyncCallbackInfo->native_data.data_type = NVT_NONE;
    if (asyncCallbackInfo->ability == nullptr) {
        asyncCallbackInfo->error_code = NAPI_ERR_ACE_ABILITY;
        return;
    }
#ifdef SUPPORT_SCREEN
    int orientation = asyncCallbackInfo->param.paramArgs.GetIntValue("orientation");
    asyncCallbackInfo->ability->SetDisplayOrientation(orientation);
#endif
    asyncCallbackInfo->native_data.data_type = NVT_UNDEFINED;
}

napi_value NAPI_SetDisplayOrientationWrap(napi_env env, napi_callback_info info, AsyncJSCallbackInfo *asyncCallbackInfo)
{
    TAG_LOGD(AAFwkTag::JSNAPI, "called");
    size_t argc = ARGS_MAX_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    napi_value jsthis = nullptr;
    void *data = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, &jsthis, &data));

    if (!UnwrapSetDisplayOrientation(env, argc, args, asyncCallbackInfo)) {
        TAG_LOGE(AAFwkTag::JSNAPI, "UnwrapSetDisplayOrientation fail");
        return nullptr;
    }

    AsyncParamEx asyncParamEx;
    if (asyncCallbackInfo->cbInfo.callback != nullptr) {
        asyncParamEx.resource = "NAPI_SetDisplayOrientationCallback";
        asyncParamEx.execute = SetDisplayOrientationExecuteCallbackWork;
        asyncParamEx.complete = CompleteAsyncCallbackWork;

        return ExecuteAsyncCallbackWork(env, asyncCallbackInfo, &asyncParamEx);
    } else {
        asyncParamEx.resource = "NAPI_SetDisplayOrientationPromise";
        asyncParamEx.execute = SetDisplayOrientationExecuteCallbackWork;
        asyncParamEx.complete = CompletePromiseCallbackWork;

        return ExecutePromiseCallbackWork(env, asyncCallbackInfo, &asyncParamEx);
    }
}

napi_value NAPI_SetShowOnLockScreen(napi_env env, napi_callback_info info)
{
#ifdef SUPPORT_GRAPHICS
    TAG_LOGI(AAFwkTag::JSNAPI, "called");

    size_t argc = 2;
    const size_t argcAsync = 2, argcPromise = 1;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr));
    if (argc != argcAsync && argc != argcPromise) {
        TAG_LOGE(AAFwkTag::JSNAPI, "invalid argc");
        return nullptr;
    }

    napi_valuetype valuetypeParam0 = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[PARAM0], &valuetypeParam0));
    if (valuetypeParam0 != napi_boolean) {
        TAG_LOGE(AAFwkTag::JSNAPI, "error type");
        return nullptr;
    }

    ShowOnLockScreenCB *showOnLockScreenCB = new ShowOnLockScreenCB();
    showOnLockScreenCB->cbBase.cbInfo.env = env;
    showOnLockScreenCB->cbBase.abilityType = AbilityType::PAGE;
    if (!UnwrapBoolFromJS2(env, args[PARAM0], showOnLockScreenCB->isShow)) {
        TAG_LOGE(AAFwkTag::JSNAPI, "unwrapBoolFromJS2 error");
        delete showOnLockScreenCB;
        showOnLockScreenCB = nullptr;
        return nullptr;
    }

    showOnLockScreenCB->cbBase.ability = GetJSAbilityObject(env);
    napi_value ret = nullptr;
    if (argc == argcAsync) {
        ret = SetShowOnLockScreenAsync(env, args, showOnLockScreenCB);
    } else {
        ret = SetShowOnLockScreenPromise(env, showOnLockScreenCB);
    }

    if (ret == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "SetShowOnLockScreenWrap failed");
        delete showOnLockScreenCB;
        showOnLockScreenCB = nullptr;
        ret = WrapVoidToJS(env);
    }
    return ret;
#else
   return nullptr;
#endif
}
#endif

bool UnwrapParamVerifySelfPermission(
    napi_env env, size_t argc, napi_value *argv, AsyncJSCallbackInfo *asyncCallbackInfo)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called, argc=%{public}zu", argc);

    const size_t argcMax = 2;
    if (argc > argcMax || argc < argcMax - 1) {
        TAG_LOGE(AAFwkTag::JSNAPI, "invalid argc");
        return false;
    }

    if (argc == argcMax) {
        if (!CreateAsyncCallback(env, argv[PARAM1], asyncCallbackInfo)) {
            TAG_LOGE(AAFwkTag::JSNAPI, "argv[PARAM1] invalid");
            return false;
        }
    }

    std::string permission("");
    if (!UnwrapStringFromJS2(env, argv[PARAM0], permission)) {
        TAG_LOGE(AAFwkTag::JSNAPI, "argv[PARAM0] invalid");
        return false;
    }

    asyncCallbackInfo->param.paramArgs.PutStringValue("permission", permission);
    return true;
}

void VerifySelfPermissionExecuteCallbackWork(napi_env env, void *data)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");

    AsyncJSCallbackInfo *asyncCallbackInfo = static_cast<AsyncJSCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null asyncCallbackInfo");
        return;
    }

    asyncCallbackInfo->error_code = NAPI_ERR_NO_ERROR;
    asyncCallbackInfo->native_data.data_type = NVT_NONE;

    if (asyncCallbackInfo->ability == nullptr) {
        asyncCallbackInfo->error_code = NAPI_ERR_ACE_ABILITY;
        return;
    }

    asyncCallbackInfo->native_data.data_type = NVT_INT32;
    asyncCallbackInfo->native_data.int32_value = asyncCallbackInfo->ability->VerifySelfPermission(
        asyncCallbackInfo->param.paramArgs.GetStringValue("permission"));
}

napi_value NAPI_VerifySelfPermissionWrap(napi_env env, napi_callback_info info, AsyncJSCallbackInfo *asyncCallbackInfo)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    size_t argc = ARGS_MAX_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    napi_value jsthis = nullptr;
    void *data = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, &jsthis, &data));

    if (!UnwrapParamVerifySelfPermission(env, argc, args, asyncCallbackInfo)) {
        TAG_LOGE(AAFwkTag::JSNAPI, "UnwrapParamVerifySelfPermission fail");
        return nullptr;
    }

    AsyncParamEx asyncParamEx;
    if (asyncCallbackInfo->cbInfo.callback != nullptr) {
        asyncParamEx.resource = "NAPI_VerifySelfPermissionCallback";
        asyncParamEx.execute = VerifySelfPermissionExecuteCallbackWork;
        asyncParamEx.complete = CompleteAsyncCallbackWork;

        return ExecuteAsyncCallbackWork(env, asyncCallbackInfo, &asyncParamEx);
    } else {
        asyncParamEx.resource = "NAPI_VerifySelfPermissionPromise";
        asyncParamEx.execute = VerifySelfPermissionExecuteCallbackWork;
        asyncParamEx.complete = CompletePromiseCallbackWork;

        return ExecutePromiseCallbackWork(env, asyncCallbackInfo, &asyncParamEx);
    }
}

bool UnwrapRequestPermissionsFromUser(
    napi_env env, size_t argc, napi_value *argv, AsyncJSCallbackInfo *asyncCallbackInfo)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called, argc=%{public}zu", argc);

    const size_t argcMax = 3;
    if (argc > argcMax || argc < argcMax - 1) {
        TAG_LOGE(AAFwkTag::JSNAPI, "invalid argc");
        return false;
    }

    if (argc == argcMax) {
        if (!CreateAsyncCallback(env, argv[PARAM2], asyncCallbackInfo)) {
            TAG_LOGE(AAFwkTag::JSNAPI, "argv[PARAM2] invalid");
            return false;
        }
    }

    std::vector<std::string> permissionList;
    if (!UnwrapArrayStringFromJS(env, argv[PARAM0], permissionList)) {
        TAG_LOGE(AAFwkTag::JSNAPI, "argv[PARAM0] invalid");
        return false;
    }

    int requestCode = 0;
    if (!UnwrapInt32FromJS2(env, argv[PARAM1], requestCode)) {
        TAG_LOGE(AAFwkTag::JSNAPI, "argv[PARAM1] invalid");
        return false;
    }

    asyncCallbackInfo->param.paramArgs.PutIntValue("requestCode", requestCode);
    asyncCallbackInfo->param.paramArgs.PutStringValueArray("permissionList", permissionList);
    return true;
}

void RequestPermissionsFromUserExecuteCallbackWork(napi_env env, void *data)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    AsyncJSCallbackInfo *asyncCallbackInfo = static_cast<AsyncJSCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null asyncCallbackInfo");
        return;
    }

    asyncCallbackInfo->error_code = NAPI_ERR_NO_ERROR;
    if (asyncCallbackInfo->ability == nullptr) {
        asyncCallbackInfo->error_code = NAPI_ERR_ACE_ABILITY;
        return;
    }

    CallAbilityPermissionParam permissionParam;
    permissionParam.requestCode = asyncCallbackInfo->param.paramArgs.GetIntValue("requestCode");
    asyncCallbackInfo->param.paramArgs.GetStringValueArray("permissionList", permissionParam.permission_list);
    if (permissionParam.permission_list.size() == 0) {
        asyncCallbackInfo->error_code = NAPI_ERR_PARAM_INVALID;
        return;
    }

    AbilityProcess::GetInstance()->RequestPermissionsFromUser(
        asyncCallbackInfo->ability, permissionParam, asyncCallbackInfo->cbInfo);
}

void RequestPermissionsFromUserCompleteAsyncCallbackWork(napi_env env, napi_status status, void *data)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");

    AsyncJSCallbackInfo *asyncCallbackInfo = static_cast<AsyncJSCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null asyncCallbackInfo");
        return;
    }

    if (asyncCallbackInfo->error_code != NAPI_ERR_NO_ERROR) {
        napi_value callback = nullptr;
        napi_value undefined = nullptr;
        napi_get_undefined(env, &undefined);
        napi_value callResult = nullptr;
        napi_value revParam[ARGS_TWO] = {nullptr};

        revParam[PARAM0] = GetCallbackErrorValue(env, asyncCallbackInfo->error_code);
        revParam[PARAM1] = WrapVoidToJS(env);

        if (asyncCallbackInfo->cbInfo.callback != nullptr) {
            napi_get_reference_value(env, asyncCallbackInfo->cbInfo.callback, &callback);
            napi_call_function(env, undefined, callback, ARGS_TWO, revParam, &callResult);
            napi_delete_reference(env, asyncCallbackInfo->cbInfo.callback);
        } else if (asyncCallbackInfo->cbInfo.deferred != nullptr) {
            napi_reject_deferred(env, asyncCallbackInfo->cbInfo.deferred, revParam[PARAM0]);
        }
    }

    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    delete asyncCallbackInfo;
    asyncCallbackInfo = nullptr;
}

napi_value NAPI_RequestPermissionsFromUserWrap(
    napi_env env, napi_callback_info info, AsyncJSCallbackInfo *asyncCallbackInfo)
{
    TAG_LOGD(AAFwkTag::JSNAPI, "called");
    size_t argc = ARGS_MAX_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    napi_value jsthis = nullptr;
    void *data = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, &jsthis, &data));

    if (!UnwrapRequestPermissionsFromUser(env, argc, args, asyncCallbackInfo)) {
        TAG_LOGE(AAFwkTag::JSNAPI, "UnwrapRequestPermissionsFromUser failed");
        return nullptr;
    }

    AsyncParamEx asyncParamEx;
    if (asyncCallbackInfo->cbInfo.callback != nullptr) {
        asyncParamEx.resource = "NAPI_RequestPermissionsFromUserCallback";
        asyncParamEx.execute = RequestPermissionsFromUserExecuteCallbackWork;
        asyncParamEx.complete = RequestPermissionsFromUserCompleteAsyncCallbackWork;

        return ExecuteAsyncCallbackWork(env, asyncCallbackInfo, &asyncParamEx);
    } else {
        napi_deferred deferred = nullptr;
        napi_value promise = nullptr;
        NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->cbInfo.deferred = deferred;

        napi_value resourceName = nullptr;
        NAPI_CALL(env, napi_create_string_latin1(env, "NAPI_RequestPermissionsFromUserPromise",
            NAPI_AUTO_LENGTH, &resourceName));
        NAPI_CALL(env,
            napi_create_async_work(env,
                nullptr,
                resourceName,
                RequestPermissionsFromUserExecuteCallbackWork,
                RequestPermissionsFromUserCompleteAsyncCallbackWork,
                static_cast<void *>(asyncCallbackInfo),
                &asyncCallbackInfo->asyncWork));

        NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

        return promise;
    }
}

void GetAppInfoExecuteCB(napi_env env, void *data)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    AppInfoCB *appInfoCB = static_cast<AppInfoCB *>(data);
    appInfoCB->cbBase.errCode = NAPI_ERR_NO_ERROR;

    if (appInfoCB->cbBase.ability == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null ability");
        appInfoCB->cbBase.errCode = NAPI_ERR_ACE_ABILITY;
        return;
    }

    std::shared_ptr<ApplicationInfo> appInfoPtr = appInfoCB->cbBase.ability->GetApplicationInfo();
    if (appInfoPtr != nullptr) {
        appInfoCB->appInfo = *appInfoPtr;
    } else {
        TAG_LOGE(AAFwkTag::JSNAPI, "null appInfoPtr");
        appInfoCB->cbBase.errCode = NAPI_ERR_ABILITY_CALL_INVALID;
    }
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
}

void GetAppInfoAsyncCompleteCB(napi_env env, napi_status status, void *data)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    AppInfoCB *appInfoCB = static_cast<AppInfoCB *>(data);
    napi_value callback = nullptr;
    napi_value undefined = nullptr;
    napi_value result[ARGS_TWO] = {nullptr};
    napi_value callResult = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
    result[PARAM0] = GetCallbackErrorValue(env, appInfoCB->cbBase.errCode);
    if (appInfoCB->cbBase.errCode == NAPI_ERR_NO_ERROR) {
        result[PARAM1] = WrapAppInfo(env, appInfoCB->appInfo);
    } else {
        result[PARAM1] = WrapUndefinedToJS(env);
    }
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, appInfoCB->cbBase.cbInfo.callback, &callback));
    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, ARGS_TWO, &result[PARAM0], &callResult));

    if (appInfoCB->cbBase.cbInfo.callback != nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, appInfoCB->cbBase.cbInfo.callback));
    }
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, appInfoCB->cbBase.asyncWork));
    delete appInfoCB;
    appInfoCB = nullptr;
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
}

napi_value GetApplicationInfoAsync(napi_env env, napi_value *args, const size_t argCallback, AppInfoCB *appInfoCB)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    if (args == nullptr || appInfoCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null param");
        return nullptr;
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[argCallback], &valuetype));
    if (valuetype == napi_function) {
        NAPI_CALL(env, napi_create_reference(env, args[argCallback], 1, &appInfoCB->cbBase.cbInfo.callback));
    }
    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            GetAppInfoExecuteCB,
            GetAppInfoAsyncCompleteCB,
            static_cast<void *>(appInfoCB),
            &appInfoCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, appInfoCB->cbBase.asyncWork, napi_qos_user_initiated));
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return result;
}

void GetAppInfoPromiseCompleteCB(napi_env env, napi_status status, void *data)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    AppInfoCB *appInfoCB = static_cast<AppInfoCB *>(data);
    if (appInfoCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null appInfoCB");
        return;
    }

    napi_value result = nullptr;
    if (appInfoCB->cbBase.errCode == NAPI_ERR_NO_ERROR) {
        result = WrapAppInfo(env, appInfoCB->appInfo);
        napi_resolve_deferred(env, appInfoCB->cbBase.deferred, result);
    } else {
        result = GetCallbackErrorValue(env, appInfoCB->cbBase.errCode);
        napi_reject_deferred(env, appInfoCB->cbBase.deferred, result);
    }

    napi_delete_async_work(env, appInfoCB->cbBase.asyncWork);
    delete appInfoCB;
    appInfoCB = nullptr;
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
}

napi_value GetApplicationInfoPromise(napi_env env, AppInfoCB *appInfoCB)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "promise");
    if (appInfoCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null appInfoCB");
        return nullptr;
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    napi_deferred deferred;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    appInfoCB->cbBase.deferred = deferred;

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            GetAppInfoExecuteCB,
            GetAppInfoPromiseCompleteCB,
            static_cast<void *>(appInfoCB),
            &appInfoCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, appInfoCB->cbBase.asyncWork, napi_qos_user_initiated));
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return promise;
}

napi_value GetApplicationInfoWrap(napi_env env, napi_callback_info info, AppInfoCB *appInfoCB)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    if (appInfoCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null appInfoCB");
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
        ret = GetApplicationInfoAsync(env, args, 0, appInfoCB);
    } else {
        ret = GetApplicationInfoPromise(env, appInfoCB);
    }
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return ret;
}

AppInfoCB *CreateAppInfoCBInfo(napi_env env)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    napi_value global = nullptr;
    NAPI_CALL(env, napi_get_global(env, &global));

    napi_value abilityObj = nullptr;
    NAPI_CALL(env, napi_get_named_property(env, global, "ability", &abilityObj));

    Ability *ability = nullptr;
    NAPI_CALL(env, napi_get_value_external(env, abilityObj, reinterpret_cast<void **>(&ability)));

    AppInfoCB *appInfoCB = new (std::nothrow) AppInfoCB;
    if (appInfoCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null appInfoCB");
        return nullptr;
    }
    appInfoCB->cbBase.cbInfo.env = env;
    appInfoCB->cbBase.asyncWork = nullptr;
    appInfoCB->cbBase.deferred = nullptr;
    appInfoCB->cbBase.ability = ability;
    appInfoCB->cbBase.abilityType = AbilityType::UNKNOWN;
    appInfoCB->cbBase.errCode = NAPI_ERR_NO_ERROR;

    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return appInfoCB;
}

napi_value NAPI_VerifySelfPermission(napi_env env, napi_callback_info info)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");

    AsyncJSCallbackInfo *asyncCallbackInfo = CreateAsyncJSCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }

    napi_value rev = NAPI_VerifySelfPermissionWrap(env, info, asyncCallbackInfo);
    if (rev == nullptr) {
        FreeAsyncJSCallbackInfo(&asyncCallbackInfo);
        rev = WrapVoidToJS(env);
    }
    return rev;
}

napi_value NAPI_RequestPermissionsFromUser(napi_env env, napi_callback_info info)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");

    AsyncJSCallbackInfo *asyncCallbackInfo = CreateAsyncJSCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        TAG_LOGI(AAFwkTag::JSNAPI, "null asyncCallbackInfo");
        return WrapVoidToJS(env);
    }

    napi_value rev = NAPI_RequestPermissionsFromUserWrap(env, info, asyncCallbackInfo);
    if (rev == nullptr) {
        FreeAsyncJSCallbackInfo(&asyncCallbackInfo);
        rev = WrapVoidToJS(env);
    }
    return rev;
}

napi_value NAPI_GetFilesDir(napi_env env, napi_callback_info info)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    return NAPI_GetFilesDirCommon(env, info, AbilityType::PAGE);
}

napi_value NAPI_GetOrCreateDistributedDir(napi_env env, napi_callback_info info)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    return NAPI_GetOrCreateDistributedDirCommon(env, info, AbilityType::PAGE);
}

napi_value NAPI_GetCacheDir(napi_env env, napi_callback_info info)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    return NAPI_GetCacheDirCommon(env, info, AbilityType::PAGE);
}

napi_value NAPI_GetCtxAppType(napi_env env, napi_callback_info info)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    return NAPI_GetAppTypeCommon(env, info, AbilityType::PAGE);
}

napi_value NAPI_GetCtxHapModuleInfo(napi_env env, napi_callback_info info)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    return NAPI_GetHapModuleInfoCommon(env, info, AbilityType::PAGE);
}

napi_value NAPI_GetAppVersionInfo(napi_env env, napi_callback_info info)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    return NAPI_GetAppVersionInfoCommon(env, info, AbilityType::PAGE);
}

napi_value NAPI_GetApplicationContext(napi_env env, napi_callback_info info)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    return NAPI_GetContextCommon(env, info, AbilityType::PAGE);
}

napi_value NAPI_GetCtxAbilityInfo(napi_env env, napi_callback_info info)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    return NAPI_GetAbilityInfoCommon(env, info, AbilityType::PAGE);
}

bool UnwrapVerifyPermissionOptions(napi_env env, napi_value argv, AsyncJSCallbackInfo *asyncCallbackInfo)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    if (asyncCallbackInfo == nullptr) {
        TAG_LOGI(AAFwkTag::JSNAPI, "null asyncCallbackInfo");
        return false;
    }

    if (!IsTypeForNapiValue(env, argv, napi_object)) {
        TAG_LOGI(AAFwkTag::JSNAPI, "wrong param type");
        return false;
    }

    int value = 0;
    if (UnwrapInt32ByPropertyName(env, argv, "pid", value)) {
        asyncCallbackInfo->param.paramArgs.PutIntValue("pid", value);
    }

    value = 0;
    if (UnwrapInt32ByPropertyName(env, argv, "uid", value)) {
        asyncCallbackInfo->param.paramArgs.PutIntValue("uid", value);
    }
    return true;
}

bool UnwrapParamVerifyPermission(napi_env env, size_t argc, napi_value *argv, AsyncJSCallbackInfo *asyncCallbackInfo)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "argc=%{public}zu", argc);

    const size_t argcMax = ARGS_THREE;
    if (argc > argcMax || argc < 1) {
        TAG_LOGI(AAFwkTag::JSNAPI, "invalid argc");
        return false;
    }

    std::string permission("");
    if (!UnwrapStringFromJS2(env, argv[PARAM0], permission)) {
        TAG_LOGI(AAFwkTag::JSNAPI, "invalid argv[PARAM0]");
        return false;
    }
    asyncCallbackInfo->param.paramArgs.PutStringValue("permission", permission);

    if (argc == argcMax) {
        if (!CreateAsyncCallback(env, argv[PARAM2], asyncCallbackInfo)) {
            TAG_LOGI(AAFwkTag::JSNAPI, "invalid argv[PARAM2]");
            return false;
        }

        if (!UnwrapVerifyPermissionOptions(env, argv[PARAM1], asyncCallbackInfo)) {
            TAG_LOGI(AAFwkTag::JSNAPI, "invalid argv[PARAM1]");
            return false;
        }
    } else if (argc == ARGS_TWO) {
        if (!CreateAsyncCallback(env, argv[PARAM1], asyncCallbackInfo)) {
            if (!UnwrapVerifyPermissionOptions(env, argv[PARAM1], asyncCallbackInfo)) {
                TAG_LOGI(AAFwkTag::JSNAPI, "invalid argv[PARAM1]");
                return false;
            }
        }
    } else if (argc == ARGS_ONE) {
        asyncCallbackInfo->cbInfo.callback = nullptr;
    } else {
        TAG_LOGI(AAFwkTag::JSNAPI, "invalid argc");
        return false;
    }
    return true;
}

void VerifyPermissionExecuteCallback(napi_env env, void *data)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");

    AsyncJSCallbackInfo *asyncCallbackInfo = static_cast<AsyncJSCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        TAG_LOGI(AAFwkTag::JSNAPI, "null asyncCallbackInfo");
        return;
    }

    asyncCallbackInfo->error_code = NAPI_ERR_NO_ERROR;
    asyncCallbackInfo->native_data.data_type = NVT_NONE;

    if (asyncCallbackInfo->ability == nullptr) {
        asyncCallbackInfo->error_code = NAPI_ERR_ACE_ABILITY;
        return;
    }

    std::string permission(asyncCallbackInfo->param.paramArgs.GetStringValue("permission").c_str());
    bool hasUid = asyncCallbackInfo->param.paramArgs.HasKey("uid");
    int pid = asyncCallbackInfo->param.paramArgs.GetIntValue("pid");
    int uid = asyncCallbackInfo->param.paramArgs.GetIntValue("uid");

    asyncCallbackInfo->native_data.data_type = NVT_INT32;

    if (hasUid) {
        asyncCallbackInfo->native_data.int32_value = asyncCallbackInfo->ability->VerifyPermission(permission, pid, uid);
    } else {
        asyncCallbackInfo->native_data.int32_value = asyncCallbackInfo->ability->VerifySelfPermission(permission);
    }
}

napi_value NAPI_VerifyPermissionWrap(napi_env env, napi_callback_info info, AsyncJSCallbackInfo *asyncCallbackInfo)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    size_t argc = ARGS_MAX_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    napi_value jsthis = nullptr;
    void *data = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, &jsthis, &data));

    if (!UnwrapParamVerifyPermission(env, argc, args, asyncCallbackInfo)) {
        TAG_LOGI(AAFwkTag::JSNAPI, "unwrapParamVerifyPermission failed");
        return nullptr;
    }

    AsyncParamEx asyncParamEx;
    if (asyncCallbackInfo->cbInfo.callback != nullptr) {
        TAG_LOGI(AAFwkTag::JSNAPI, "asyncCallback");
        asyncParamEx.resource = "NAPI_VerifyPermissionCallback";
        asyncParamEx.execute = VerifyPermissionExecuteCallback;
        asyncParamEx.complete = CompleteAsyncCallbackWork;

        return ExecuteAsyncCallbackWork(env, asyncCallbackInfo, &asyncParamEx);
    } else {
        TAG_LOGI(AAFwkTag::JSNAPI, "promise");
        asyncParamEx.resource = "NAPI_VerifyPermissionPromise";
        asyncParamEx.execute = VerifyPermissionExecuteCallback;
        asyncParamEx.complete = CompletePromiseCallbackWork;

        return ExecutePromiseCallbackWork(env, asyncCallbackInfo, &asyncParamEx);
    }
}

napi_value NAPI_VerifyPermission(napi_env env, napi_callback_info info)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    AsyncJSCallbackInfo *asyncCallbackInfo = CreateAsyncJSCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        TAG_LOGI(AAFwkTag::JSNAPI, "null asyncCallbackInfo");
        return WrapVoidToJS(env);
    }

    napi_value rev = NAPI_VerifyPermissionWrap(env, info, asyncCallbackInfo);
    if (rev == nullptr) {
        FreeAsyncJSCallbackInfo(&asyncCallbackInfo);
        rev = WrapVoidToJS(env);
    }
    return rev;
}

void GetBundleNameExecuteCallback(napi_env env, void *data)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    AsyncJSCallbackInfo *asyncCallbackInfo = static_cast<AsyncJSCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null asyncCallbackInfo");
        return;
    }

    asyncCallbackInfo->error_code = NAPI_ERR_NO_ERROR;
    asyncCallbackInfo->native_data.data_type = NVT_NONE;
    if (asyncCallbackInfo->ability == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null ability");
        asyncCallbackInfo->error_code = NAPI_ERR_ACE_ABILITY;
        return;
    }

    asyncCallbackInfo->native_data.data_type = NVT_STRING;
    asyncCallbackInfo->native_data.str_value = asyncCallbackInfo->ability->GetBundleName();
    TAG_LOGI(AAFwkTag::JSNAPI, "bundleName=%{public}s",
             asyncCallbackInfo->native_data.str_value.c_str());
}

napi_value NAPI_GetBundleNameWrap(napi_env env, napi_callback_info info, AsyncJSCallbackInfo *asyncCallbackInfo)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    size_t argc = ARGS_MAX_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    napi_value jsthis = nullptr;
    void *data = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, &jsthis, &data));

    if (argc > ARGS_ONE) {
        TAG_LOGI(AAFwkTag::JSNAPI, "invalid argc");
        return nullptr;
    }

    if (argc == ARGS_ONE) {
        if (!CreateAsyncCallback(env, args[PARAM0], asyncCallbackInfo)) {
            TAG_LOGI(AAFwkTag::JSNAPI, "invalid args[PARAM0]");
            return nullptr;
        }
    }

    AsyncParamEx asyncParamEx;
    if (asyncCallbackInfo->cbInfo.callback != nullptr) {
        TAG_LOGI(AAFwkTag::JSNAPI, "asyncCallback");
        asyncParamEx.resource = "NAPI_GetBundleNameCallback";
        asyncParamEx.execute = GetBundleNameExecuteCallback;
        asyncParamEx.complete = CompleteAsyncCallbackWork;

        return ExecuteAsyncCallbackWork(env, asyncCallbackInfo, &asyncParamEx);
    } else {
        TAG_LOGI(AAFwkTag::JSNAPI, "promise");
        asyncParamEx.resource = "NAPI_GetBundleNamePromise";
        asyncParamEx.execute = GetBundleNameExecuteCallback;
        asyncParamEx.complete = CompletePromiseCallbackWork;

        return ExecutePromiseCallbackWork(env, asyncCallbackInfo, &asyncParamEx);
    }
}

napi_value WrapProcessInfo(napi_env env, ProcessInfoCB *processInfoCB)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    if (processInfoCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null processInfoCB");
        return nullptr;
    }
    napi_value result = nullptr;
    napi_value proValue = nullptr;
    NAPI_CALL(env, napi_create_object(env, &result));
    NAPI_CALL(env, napi_create_int32(env, processInfoCB->pid, &proValue));
    NAPI_CALL(env, napi_set_named_property(env, result, "pid", proValue));

    NAPI_CALL(env, napi_create_string_utf8(env, processInfoCB->processName.c_str(), NAPI_AUTO_LENGTH, &proValue));
    NAPI_CALL(env, napi_set_named_property(env, result, "processName", proValue));
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return result;
}

void GetProcessInfoExecuteCB(napi_env env, void *data)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "execute");
    ProcessInfoCB *processInfoCB = static_cast<ProcessInfoCB *>(data);
    if (processInfoCB == nullptr) {
        return;
    }

    processInfoCB->cbBase.errCode = NAPI_ERR_NO_ERROR;
    if (processInfoCB->cbBase.ability == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null ability");
        processInfoCB->cbBase.errCode = NAPI_ERR_ACE_ABILITY;
        return;
    }

    std::shared_ptr<ProcessInfo> processInfoPtr = processInfoCB->cbBase.ability->GetProcessInfo();
    if (processInfoPtr != nullptr) {
        processInfoCB->processName = processInfoPtr->GetProcessName();
        processInfoCB->pid = processInfoPtr->GetPid();
    } else {
        TAG_LOGE(AAFwkTag::JSNAPI, "null processInfoPtr");
        processInfoCB->cbBase.errCode = NAPI_ERR_ABILITY_CALL_INVALID;
    }
    TAG_LOGI(AAFwkTag::JSNAPI, "execute end");
}

void GetProcessInfoAsyncCompleteCB(napi_env env, napi_status status, void *data)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "complete");
    ProcessInfoCB *processInfoCB = static_cast<ProcessInfoCB *>(data);
    napi_value callback = nullptr;
    napi_value undefined = nullptr;
    napi_value result[ARGS_TWO] = {nullptr};
    napi_value callResult = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
    result[PARAM0] = GetCallbackErrorValue(env, processInfoCB->cbBase.errCode);
    if (processInfoCB->cbBase.errCode == NAPI_ERR_NO_ERROR) {
        result[PARAM1] = WrapProcessInfo(env, processInfoCB);
    } else {
        result[PARAM1] = WrapUndefinedToJS(env);
    }

    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, processInfoCB->cbBase.cbInfo.callback, &callback));
    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, ARGS_TWO, &result[PARAM0], &callResult));

    if (processInfoCB->cbBase.cbInfo.callback != nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, processInfoCB->cbBase.cbInfo.callback));
    }
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, processInfoCB->cbBase.asyncWork));
    delete processInfoCB;
    processInfoCB = nullptr;
    TAG_LOGI(AAFwkTag::JSNAPI, "complete end");
}

napi_value GetProcessInfoAsync(napi_env env, napi_value *args, const size_t argCallback, ProcessInfoCB *processInfoCB)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    if (args == nullptr || processInfoCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null param");
        return nullptr;
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[argCallback], &valuetype));
    if (valuetype == napi_function) {
        NAPI_CALL(env, napi_create_reference(env, args[argCallback], 1, &processInfoCB->cbBase.cbInfo.callback));
    }
    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            GetProcessInfoExecuteCB,
            GetProcessInfoAsyncCompleteCB,
            static_cast<void *>(processInfoCB),
            &processInfoCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, processInfoCB->cbBase.asyncWork, napi_qos_user_initiated));
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return result;
}

void GetProcessInfoPromiseCompleteCB(napi_env env, napi_status status, void *data)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "complete");
    ProcessInfoCB *processInfoCB = static_cast<ProcessInfoCB *>(data);
    napi_value result = nullptr;
    if (processInfoCB->cbBase.errCode == NAPI_ERR_NO_ERROR) {
        result = WrapProcessInfo(env, processInfoCB);
        napi_resolve_deferred(env, processInfoCB->cbBase.deferred, result);
    } else {
        result = GetCallbackErrorValue(env, processInfoCB->cbBase.errCode);
        napi_reject_deferred(env, processInfoCB->cbBase.deferred, result);
    }

    napi_delete_async_work(env, processInfoCB->cbBase.asyncWork);
    delete processInfoCB;
    processInfoCB = nullptr;
    TAG_LOGI(AAFwkTag::JSNAPI, "complete end");
}

napi_value GetProcessInfoPromise(napi_env env, ProcessInfoCB *processInfoCB)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    if (processInfoCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null processInfoCB");
        return nullptr;
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    napi_deferred deferred;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    processInfoCB->cbBase.deferred = deferred;

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            GetProcessInfoExecuteCB,
            GetProcessInfoPromiseCompleteCB,
            static_cast<void *>(processInfoCB),
            &processInfoCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, processInfoCB->cbBase.asyncWork, napi_qos_user_initiated));
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return promise;
}

napi_value GetProcessInfoWrap(napi_env env, napi_callback_info info, ProcessInfoCB *processInfoCB)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "asyncCallback");
    if (processInfoCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null processInfoCB");
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
        ret = GetProcessInfoAsync(env, args, 0, processInfoCB);
    } else {
        ret = GetProcessInfoPromise(env, processInfoCB);
    }
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return ret;
}

ProcessInfoCB *CreateProcessInfoCBInfo(napi_env env)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    napi_value global = nullptr;
    NAPI_CALL(env, napi_get_global(env, &global));

    napi_value abilityObj = nullptr;
    NAPI_CALL(env, napi_get_named_property(env, global, "ability", &abilityObj));

    Ability *ability = nullptr;
    NAPI_CALL(env, napi_get_value_external(env, abilityObj, reinterpret_cast<void **>(&ability)));

    ProcessInfoCB *processInfoCB = new (std::nothrow) ProcessInfoCB;
    if (processInfoCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null processInfoCB");
        return nullptr;
    }
    processInfoCB->cbBase.cbInfo.env = env;
    processInfoCB->cbBase.asyncWork = nullptr;
    processInfoCB->cbBase.deferred = nullptr;
    processInfoCB->cbBase.ability = ability;

    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return processInfoCB;
}

ElementNameCB *CreateElementNameCBInfo(napi_env env)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    napi_value global = nullptr;
    NAPI_CALL(env, napi_get_global(env, &global));

    napi_value abilityObj = nullptr;
    NAPI_CALL(env, napi_get_named_property(env, global, "ability", &abilityObj));

    Ability *ability = nullptr;
    NAPI_CALL(env, napi_get_value_external(env, abilityObj, reinterpret_cast<void **>(&ability)));

    ElementNameCB *elementNameCB = new (std::nothrow) ElementNameCB;
    if (elementNameCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null elementNameCB");
        return nullptr;
    }
    elementNameCB->cbBase.cbInfo.env = env;
    elementNameCB->cbBase.asyncWork = nullptr;
    elementNameCB->cbBase.deferred = nullptr;
    elementNameCB->cbBase.ability = ability;

    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return elementNameCB;
}

napi_value WrapElementName(napi_env env, const ElementNameCB *elementNameCB)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    if (elementNameCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null elementNameCB");
        return nullptr;
    }
    napi_value result = nullptr;
    napi_value proValue = nullptr;
    NAPI_CALL(env, napi_create_object(env, &result));
    NAPI_CALL(env, napi_create_string_utf8(env, elementNameCB->abilityName.c_str(), NAPI_AUTO_LENGTH, &proValue));
    NAPI_CALL(env, napi_set_named_property(env, result, "abilityName", proValue));

    NAPI_CALL(env, napi_create_string_utf8(env, elementNameCB->bundleName.c_str(), NAPI_AUTO_LENGTH, &proValue));
    NAPI_CALL(env, napi_set_named_property(env, result, "bundleName", proValue));

    NAPI_CALL(env, napi_create_string_utf8(env, elementNameCB->deviceId.c_str(), NAPI_AUTO_LENGTH, &proValue));
    NAPI_CALL(env, napi_set_named_property(env, result, "deviceId", proValue));

    NAPI_CALL(env, napi_create_string_utf8(env, elementNameCB->shortName.c_str(), NAPI_AUTO_LENGTH, &proValue));
    NAPI_CALL(env, napi_set_named_property(env, result, "shortName", proValue));

    NAPI_CALL(env, napi_create_string_utf8(env, elementNameCB->uri.c_str(), NAPI_AUTO_LENGTH, &proValue));
    NAPI_CALL(env, napi_set_named_property(env, result, "uri", proValue));
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return result;
}

void GetElementNameExecuteCB(napi_env env, void *data)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "execute");
    if (data == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null data");
        return;
    }
    ElementNameCB *elementNameCB = static_cast<ElementNameCB *>(data);
    if (elementNameCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null elementNameCB");
        return;
    }

    elementNameCB->cbBase.errCode = NAPI_ERR_NO_ERROR;
    if (elementNameCB->cbBase.ability == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null ability");
        elementNameCB->cbBase.errCode = NAPI_ERR_ACE_ABILITY;
        return;
    }

    std::shared_ptr<ElementName> elementName = elementNameCB->cbBase.ability->GetElementName();
    if (elementName != nullptr) {
        elementNameCB->deviceId = elementName->GetDeviceID();
        elementNameCB->bundleName = elementName->GetBundleName();
        elementNameCB->abilityName = elementName->GetAbilityName();
        elementNameCB->uri = elementNameCB->cbBase.ability->GetWant()->GetUriString();
        elementNameCB->shortName = "";
    } else {
        elementNameCB->cbBase.errCode = NAPI_ERR_ABILITY_CALL_INVALID;
    }
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
}

void GetElementNameAsyncCompleteCB(napi_env env, napi_status status, void *data)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "complete");
    ElementNameCB *elementNameCB = static_cast<ElementNameCB *>(data);
    napi_value callback = nullptr;
    napi_value undefined = nullptr;
    napi_value result[ARGS_TWO] = {nullptr};
    napi_value callResult = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
    result[PARAM0] = GetCallbackErrorValue(env, elementNameCB->cbBase.errCode);
    if (elementNameCB->cbBase.errCode == NAPI_ERR_NO_ERROR) {
        result[PARAM1] = WrapElementName(env, elementNameCB);
    } else {
        result[PARAM1] = WrapUndefinedToJS(env);
    }
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, elementNameCB->cbBase.cbInfo.callback, &callback));
    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, ARGS_TWO, &result[PARAM0], &callResult));

    if (elementNameCB->cbBase.cbInfo.callback != nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, elementNameCB->cbBase.cbInfo.callback));
    }
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, elementNameCB->cbBase.asyncWork));
    delete elementNameCB;
    elementNameCB = nullptr;
    TAG_LOGI(AAFwkTag::JSNAPI, "complete end");
}

void GetElementNamePromiseCompleteCB(napi_env env, napi_status status, void *data)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "complete");
    ElementNameCB *elementNameCB = static_cast<ElementNameCB *>(data);
    napi_value result = nullptr;
    if (elementNameCB->cbBase.errCode == NAPI_ERR_NO_ERROR) {
        result = WrapElementName(env, elementNameCB);
        napi_resolve_deferred(env, elementNameCB->cbBase.deferred, result);
    } else {
        result = GetCallbackErrorValue(env, elementNameCB->cbBase.errCode);
        napi_reject_deferred(env, elementNameCB->cbBase.deferred, result);
    }

    napi_delete_async_work(env, elementNameCB->cbBase.asyncWork);
    delete elementNameCB;
    elementNameCB = nullptr;
    TAG_LOGI(AAFwkTag::JSNAPI, "complete end");
}

napi_value GetElementNamePromise(napi_env env, ElementNameCB *elementNameCB)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    if (elementNameCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null elementNameCB");
        return nullptr;
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    napi_deferred deferred;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    elementNameCB->cbBase.deferred = deferred;

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            GetElementNameExecuteCB,
            GetElementNamePromiseCompleteCB,
            static_cast<void *>(elementNameCB),
            &elementNameCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, elementNameCB->cbBase.asyncWork, napi_qos_user_initiated));
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return promise;
}

napi_value GetElementNameAsync(napi_env env, napi_value *args, const size_t argCallback, ElementNameCB *elementNameCB)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    if (args == nullptr || elementNameCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null param");
        return nullptr;
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[argCallback], &valuetype));
    if (valuetype == napi_function) {
        NAPI_CALL(env, napi_create_reference(env, args[argCallback], 1, &elementNameCB->cbBase.cbInfo.callback));
    }
    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            GetElementNameExecuteCB,
            GetElementNameAsyncCompleteCB,
            static_cast<void *>(elementNameCB),
            &elementNameCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, elementNameCB->cbBase.asyncWork, napi_qos_user_initiated));
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return result;
}

napi_value GetElementNameWrap(napi_env env, napi_callback_info info, ElementNameCB *elementNameCB)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    if (elementNameCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null appInfoCB");
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
        ret = GetElementNameAsync(env, args, 0, elementNameCB);
    } else {
        ret = GetElementNamePromise(env, elementNameCB);
    }
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return ret;
}

ProcessNameCB *CreateProcessNameCBInfo(napi_env env)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    napi_value global = nullptr;
    NAPI_CALL(env, napi_get_global(env, &global));

    napi_value abilityObj = nullptr;
    NAPI_CALL(env, napi_get_named_property(env, global, "ability", &abilityObj));

    Ability *ability = nullptr;
    NAPI_CALL(env, napi_get_value_external(env, abilityObj, reinterpret_cast<void **>(&ability)));

    ProcessNameCB *processNameCB = new (std::nothrow) ProcessNameCB;
    if (processNameCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null processNameCB");
        return nullptr;
    }
    processNameCB->cbBase.cbInfo.env = env;
    processNameCB->cbBase.asyncWork = nullptr;
    processNameCB->cbBase.deferred = nullptr;
    processNameCB->cbBase.ability = ability;

    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return processNameCB;
}

void GetProcessNameExecuteCB(napi_env env, void *data)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    ProcessNameCB *processNameCB = static_cast<ProcessNameCB *>(data);
    if (processNameCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null processNameCB");
        return;
    }

    processNameCB->cbBase.errCode = NAPI_ERR_NO_ERROR;
    if (processNameCB->cbBase.ability == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null ability");
        processNameCB->cbBase.errCode = NAPI_ERR_ACE_ABILITY;
        return;
    }

    processNameCB->processName = processNameCB->cbBase.ability->GetProcessName();
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
}

napi_value WrapProcessName(napi_env env, const ProcessNameCB *processNameCB)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    if (processNameCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null processNameCB");
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, processNameCB->processName.c_str(), NAPI_AUTO_LENGTH, &result));
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return result;
}

void GetProcessNameAsyncCompleteCB(napi_env env, napi_status status, void *data)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "complete");
    ProcessNameCB *processNameCB = static_cast<ProcessNameCB *>(data);
    napi_value callback = nullptr;
    napi_value undefined = nullptr;
    napi_value result[ARGS_TWO] = {nullptr};
    napi_value callResult = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
    result[PARAM0] = GetCallbackErrorValue(env, processNameCB->cbBase.errCode);
    if (processNameCB->cbBase.errCode == NAPI_ERR_NO_ERROR) {
        result[PARAM1] = WrapProcessName(env, processNameCB);
    } else {
        result[PARAM1] = WrapUndefinedToJS(env);
    }
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, processNameCB->cbBase.cbInfo.callback, &callback));
    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, ARGS_TWO, &result[PARAM0], &callResult));

    if (processNameCB->cbBase.cbInfo.callback != nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, processNameCB->cbBase.cbInfo.callback));
    }
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, processNameCB->cbBase.asyncWork));
    delete processNameCB;
    processNameCB = nullptr;
    TAG_LOGI(AAFwkTag::JSNAPI, "complete end");
}

void GetProcessNamePromiseCompleteCB(napi_env env, napi_status status, void *data)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "complete");
    ProcessNameCB *processNameCB = static_cast<ProcessNameCB *>(data);
    napi_value result = nullptr;
    if (processNameCB->cbBase.errCode == NAPI_ERR_NO_ERROR) {
        result = WrapProcessName(env, processNameCB);
        napi_resolve_deferred(env, processNameCB->cbBase.deferred, result);
    } else {
        result = GetCallbackErrorValue(env, processNameCB->cbBase.errCode);
        napi_reject_deferred(env, processNameCB->cbBase.deferred, result);
    }

    napi_delete_async_work(env, processNameCB->cbBase.asyncWork);
    delete processNameCB;
    processNameCB = nullptr;
    TAG_LOGI(AAFwkTag::JSNAPI, "complete end");
}

napi_value GetProcessNameAsync(napi_env env, napi_value *args, const size_t argCallback, ProcessNameCB *processNameCB)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    if (args == nullptr || processNameCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null param");
        return nullptr;
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[argCallback], &valuetype));
    if (valuetype == napi_function) {
        NAPI_CALL(env, napi_create_reference(env, args[argCallback], 1, &processNameCB->cbBase.cbInfo.callback));
    }
    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            GetProcessNameExecuteCB,
            GetProcessNameAsyncCompleteCB,
            static_cast<void *>(processNameCB),
            &processNameCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, processNameCB->cbBase.asyncWork, napi_qos_user_initiated));
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return result;
}

napi_value GetProcessNamePromise(napi_env env, ProcessNameCB *processNameCB)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "promise");
    if (processNameCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null processNameCB");
        return nullptr;
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    napi_deferred deferred;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    processNameCB->cbBase.deferred = deferred;

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            GetProcessNameExecuteCB,
            GetProcessNamePromiseCompleteCB,
            static_cast<void *>(processNameCB),
            &processNameCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, processNameCB->cbBase.asyncWork, napi_qos_user_initiated));
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return promise;
}

napi_value GetProcessNameWrap(napi_env env, napi_callback_info info, ProcessNameCB *processNameCB)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    if (processNameCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null processNameCB");
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
        ret = GetProcessNameAsync(env, args, 0, processNameCB);
    } else {
        ret = GetProcessNamePromise(env, processNameCB);
    }
    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return ret;
}

DatabaseDirCB *CreateGetDatabaseDirCBInfo(napi_env env)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    napi_value global = nullptr;
    NAPI_CALL(env, napi_get_global(env, &global));

    napi_value abilityObj = nullptr;
    NAPI_CALL(env, napi_get_named_property(env, global, "ability", &abilityObj));

    Ability *ability = nullptr;
    NAPI_CALL(env, napi_get_value_external(env, abilityObj, reinterpret_cast<void **>(&ability)));

    DatabaseDirCB *getDatabaseDirCB = new (std::nothrow) DatabaseDirCB;
    if (getDatabaseDirCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null getDatabaseDirCB");
        return nullptr;
    }
    getDatabaseDirCB->cbBase.cbInfo.env = env;
    getDatabaseDirCB->cbBase.asyncWork = nullptr;
    getDatabaseDirCB->cbBase.deferred = nullptr;
    getDatabaseDirCB->cbBase.ability = ability;

    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return getDatabaseDirCB;
}

napi_value GetDatabaseDirWrap(napi_env env, napi_callback_info info, DatabaseDirCB *getDatabaseDirCB)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    if (getDatabaseDirCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null getDatabaseDirCB");
        return nullptr;
    }

    getDatabaseDirCB->cbBase.errCode = NAPI_ERR_NO_ERROR;
    if (getDatabaseDirCB->cbBase.ability == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null ability");
        getDatabaseDirCB->cbBase.errCode = NAPI_ERR_ACE_ABILITY;
        return nullptr;
    }

    std::string abilityName = getDatabaseDirCB->cbBase.ability->GetAbilityInfo()->name;
    std::string dataDir = getDatabaseDirCB->cbBase.ability->GetAbilityInfo()->applicationInfo.dataDir;
    std::shared_ptr<HapModuleInfo> hap = getDatabaseDirCB->cbBase.ability->GetHapModuleInfo();
    std::string moduleName = (hap != nullptr) ? hap->name : std::string();
    std::string dataDirWithModuleName = dataDir + NAPI_CONTEXT_FILE_SEPARATOR + moduleName;
    TAG_LOGI(AAFwkTag::JSNAPI, "dataDir:%{public}s moduleName:%{public}s abilityName:%{public}s",
        dataDir.c_str(),
        moduleName.c_str(),
        abilityName.c_str());

    // if dataDirWithModuleName is not exits, do nothing and return.
    if (!OHOS::FileExists(dataDirWithModuleName)) {
        getDatabaseDirCB->dataBaseDir = "";
        TAG_LOGI(AAFwkTag::JSNAPI, "dirWithModuleName:%{public}s",
            dataDirWithModuleName.c_str());
    } else {
        getDatabaseDirCB->dataBaseDir = dataDirWithModuleName + NAPI_CONTEXT_FILE_SEPARATOR + abilityName +
                                        NAPI_CONTEXT_FILE_SEPARATOR + NAPI_CONTEXT_DATABASE;
        TAG_LOGI(AAFwkTag::JSNAPI, "dataBaseDir:%{public}s",
                 getDatabaseDirCB->dataBaseDir.c_str());
        if (!OHOS::FileExists(getDatabaseDirCB->dataBaseDir)) {
            TAG_LOGE(AAFwkTag::JSNAPI, "dir not exits, create dir");
            OHOS::ForceCreateDirectory(getDatabaseDirCB->dataBaseDir);
            OHOS::ChangeModeDirectory(getDatabaseDirCB->dataBaseDir, MODE);
        }
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, getDatabaseDirCB->dataBaseDir.c_str(), NAPI_AUTO_LENGTH, &result));

    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return result;
}

PreferencesDirCB *CreateGetPreferencesDirCBInfo(napi_env env)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    napi_value global = nullptr;
    NAPI_CALL(env, napi_get_global(env, &global));

    napi_value abilityObj = nullptr;
    NAPI_CALL(env, napi_get_named_property(env, global, "ability", &abilityObj));

    Ability *ability = nullptr;
    NAPI_CALL(env, napi_get_value_external(env, abilityObj, reinterpret_cast<void **>(&ability)));

    PreferencesDirCB *getPreferencesDirCB = new (std::nothrow) PreferencesDirCB;
    if (getPreferencesDirCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null getPreferencesDirCB");
        return nullptr;
    }
    getPreferencesDirCB->cbBase.cbInfo.env = env;
    getPreferencesDirCB->cbBase.asyncWork = nullptr;
    getPreferencesDirCB->cbBase.deferred = nullptr;
    getPreferencesDirCB->cbBase.ability = ability;

    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return getPreferencesDirCB;
}

napi_value GetPreferencesDirWrap(napi_env env, napi_callback_info info, PreferencesDirCB *getPreferencesDirCB)
{
    TAG_LOGI(AAFwkTag::JSNAPI, "called");
    if (getPreferencesDirCB == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null getPreferencesDirCB");
        return nullptr;
    }

    getPreferencesDirCB->cbBase.errCode = NAPI_ERR_NO_ERROR;
    if (getPreferencesDirCB->cbBase.ability == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null ability");
        getPreferencesDirCB->cbBase.errCode = NAPI_ERR_ACE_ABILITY;
        return nullptr;
    }

    std::string abilityName = getPreferencesDirCB->cbBase.ability->GetAbilityInfo()->name;
    std::string dataDir = getPreferencesDirCB->cbBase.ability->GetAbilityInfo()->applicationInfo.dataDir;
    std::shared_ptr<HapModuleInfo> hap = getPreferencesDirCB->cbBase.ability->GetHapModuleInfo();
    std::string moduleName = (hap != nullptr) ? hap->name : std::string();
    std::string dataDirWithModuleName = dataDir + NAPI_CONTEXT_FILE_SEPARATOR + moduleName;
    TAG_LOGI(AAFwkTag::JSNAPI, "dataDir:%{public}s moduleName:%{public}s abilityName:%{public}s",
        dataDir.c_str(),
        moduleName.c_str(),
        abilityName.c_str());

    // if dataDirWithModuleName is not exits, do nothing and return.
    if (!OHOS::FileExists(dataDirWithModuleName)) {
        getPreferencesDirCB->preferencesDir = "";
        TAG_LOGI(AAFwkTag::JSNAPI, "dirWithModuleName:%{public}s", dataDirWithModuleName.c_str());
    } else {
        getPreferencesDirCB->preferencesDir = dataDirWithModuleName + NAPI_CONTEXT_FILE_SEPARATOR + abilityName +
                                              NAPI_CONTEXT_FILE_SEPARATOR + NAPI_CONTEXT_PREFERENCES;
        TAG_LOGI(AAFwkTag::JSNAPI, "preferencesDir:%{public}s", getPreferencesDirCB->preferencesDir.c_str());
        if (!OHOS::FileExists(getPreferencesDirCB->preferencesDir)) {
            TAG_LOGI(AAFwkTag::JSNAPI, "create");
            OHOS::ForceCreateDirectory(getPreferencesDirCB->preferencesDir);
            OHOS::ChangeModeDirectory(getPreferencesDirCB->preferencesDir, MODE);
        }
    }
    napi_value result = nullptr;
    NAPI_CALL(
        env, napi_create_string_utf8(env, getPreferencesDirCB->preferencesDir.c_str(), NAPI_AUTO_LENGTH, &result));

    TAG_LOGI(AAFwkTag::JSNAPI, "end");
    return result;
}
}  // namespace AppExecFwk
}  // namespace OHOS