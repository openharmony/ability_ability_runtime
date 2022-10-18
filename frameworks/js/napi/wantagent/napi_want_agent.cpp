/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "napi_want_agent.h"

#include <cstdio>
#include <cstring>
#include <pthread.h>
#include <unistd.h>

#include "ability_runtime_error_util.h"
#include "hilog_wrapper.h"
#include "js_runtime_utils.h"
#include "napi_common.h"
#include "want_agent_helper.h"
using namespace OHOS::AbilityRuntime;
namespace OHOS {
#define NAPI_ASSERT_RETURN_NULL(env, assertion, message)    \
do {                                                        \
    if (!(assertion)) {                                     \
        HILOG_INFO(message);                                \
        return nullptr;                                     \
    }                                                       \
} while (0)
namespace {
constexpr size_t ARGC_ZERO = 0;
constexpr size_t ARGC_ONE = 1;
constexpr size_t ARGC_TWO = 2;
constexpr size_t ARGC_THREE = 3;
constexpr uint8_t INDEX_ONE = 1;
constexpr uint8_t INDEX_TWO = 2;
constexpr int32_t ERR_NOT_OK = -1;
constexpr int32_t BUSINESS_ERROR_CODE_OK = 0;
constexpr int32_t PARAMETER_ERROR = -1;
} // namespace


TriggerCompleteCallBack::TriggerCompleteCallBack()
{}

TriggerCompleteCallBack::~TriggerCompleteCallBack()
{}

void TriggerCompleteCallBack::SetCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    triggerCompleteInfo_.env = env;
    triggerCompleteInfo_.ref = ref;
}

void TriggerCompleteCallBack::SetWantAgentInstance(const std::shared_ptr<WantAgent> &wantAgent)
{
    triggerCompleteInfo_.wantAgent = wantAgent;
}

NativeValue* RetErrMsg(NativeEngine &engine, NativeValue *lastParam, int32_t errorCode)
{
    HILOG_DEBUG("RetErrMsg called");
    auto complete = [err = errorCode] (NativeEngine &engine, AsyncTask &task, int32_t status) {
        HILOG_DEBUG("error information output");
        task.Reject(engine, CreateJsError(engine, err, "PARAMETER_ERROR"));
    };

    NativeValue *result = nullptr;
    AsyncTask::Schedule("RetErrMsg",
        engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));

    return result;
}

napi_value CreateErrorValue(napi_env env, int32_t errCode)
{
    HILOG_INFO("enter, errorCode[%{public}d]", errCode);
    napi_value error =  NapiGetNull(env);
    if (errCode == NO_ERROR) {
        return error;
    }

    napi_value code = nullptr;
    napi_create_int32(env, errCode, &code);

    std::string errMsg = AbilityRuntimeErrorUtil::GetErrMessage(errCode);
    napi_value message = nullptr;
    napi_create_string_utf8(env, errMsg.c_str(), NAPI_AUTO_LENGTH, &message);

    napi_create_error(env, nullptr, message, &error);
    napi_set_named_property(env, error, "code", code);
    return error;
}

void NapiThrow(napi_env env, int32_t errCode)
{
    HILOG_INFO("enter");

    napi_throw(env, CreateErrorValue(env, errCode));
}

auto OnSendFinishedUvAfterWorkCallback = [](uv_work_t *work, int status) {
    HILOG_INFO("TriggerCompleteCallBack::OnSendFinishedUvAfterWorkCallback:status = %{public}d", status);

    TriggerReceiveDataWorker *dataWorkerData = static_cast<TriggerReceiveDataWorker *>(work->data);
    if (dataWorkerData == nullptr) {
        HILOG_INFO("TriggerReceiveDataWorker instance(uv_work_t) is nullptr");
        delete work;
        return;
    }
    napi_value result[NUMBER_OF_PARAMETERS_TWO] = {0};

    result[0] = GetCallbackErrorResult(dataWorkerData->env, BUSINESS_ERROR_CODE_OK);
    napi_create_object(dataWorkerData->env, &result[1]);
    // wrap wantAgent
    napi_value wantAgentClass = nullptr;
    auto constructorcb = [](napi_env env, napi_callback_info info) -> napi_value {
        napi_value thisVar = nullptr;
        napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
        return thisVar;
    };
    napi_define_class(
        dataWorkerData->env, "WantAgentClass", NAPI_AUTO_LENGTH, constructorcb, nullptr, 0, nullptr, &wantAgentClass);
    napi_value jsWantAgent = nullptr;
    napi_new_instance(dataWorkerData->env, wantAgentClass, 0, nullptr, &jsWantAgent);
    auto finalizecb = [](napi_env env, void *data, void *hint) {};
    napi_wrap(dataWorkerData->env, jsWantAgent, (void *)dataWorkerData->wantAgent.get(), finalizecb, nullptr, nullptr);
    napi_set_named_property(dataWorkerData->env, result[1], "wantAgent", jsWantAgent);
    //  wrap want
    napi_value jsWant = WrapWant(dataWorkerData->env, dataWorkerData->want);
    napi_set_named_property(dataWorkerData->env, result[1], "want", jsWant);
    // wrap finalCode
    napi_value jsFinalCode = nullptr;
    napi_create_int32(dataWorkerData->env, dataWorkerData->resultCode, &jsFinalCode);
    napi_set_named_property(dataWorkerData->env, result[1], "finalCode", jsFinalCode);
    // wrap finalData
    napi_value jsFinalData = nullptr;
    napi_create_string_utf8(dataWorkerData->env, dataWorkerData->resultData.c_str(), NAPI_AUTO_LENGTH, &jsFinalData);
    napi_set_named_property(dataWorkerData->env, result[1], "finalData", jsFinalData);
    // wrap extraInfo
    napi_value jsExtraInfo = WrapWantParams(dataWorkerData->env, dataWorkerData->resultExtras);
    napi_set_named_property(dataWorkerData->env, result[1], "extraInfo", jsExtraInfo);

    napi_value callResult = nullptr;
    napi_value undefined = nullptr;
    napi_value callback = nullptr;
    napi_get_undefined(dataWorkerData->env, &undefined);
    napi_get_reference_value(dataWorkerData->env, dataWorkerData->ref, &callback);
    napi_call_function(dataWorkerData->env, undefined, callback, NUMBER_OF_PARAMETERS_TWO, &result[0], &callResult);

    delete dataWorkerData;
    dataWorkerData = nullptr;
    delete work;
};

void TriggerCompleteCallBack::OnSendFinished(
    const AAFwk::Want &want, int resultCode, const std::string &resultData, const AAFwk::WantParams &resultExtras)
{
    HILOG_INFO("TriggerCompleteCallBack::OnSendFinished start");
    if (triggerCompleteInfo_.ref == nullptr) {
        HILOG_INFO("triggerCompleteInfo_ CallBack is nullptr");
        return;
    }
    uv_loop_s *loop = nullptr;
#if NAPI_VERSION >= NUMBER_OF_PARAMETERS_TWO
    napi_get_uv_event_loop(triggerCompleteInfo_.env, &loop);
#endif  // NAPI_VERSION >= 2
    if (loop == nullptr) {
        HILOG_INFO("loop instance is nullptr");
        return;
    }

    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        HILOG_INFO("uv_work_t instance is nullptr");
        return;
    }
    TriggerReceiveDataWorker *dataWorker = new (std::nothrow) TriggerReceiveDataWorker();
    if (dataWorker == nullptr) {
        HILOG_INFO("TriggerReceiveDataWorker instance is nullptr");
        delete work;
        work = nullptr;
        return;
    }
    dataWorker->want = want;
    dataWorker->resultCode = resultCode;
    dataWorker->resultData = resultData;
    dataWorker->resultExtras = resultExtras;
    dataWorker->env = triggerCompleteInfo_.env;
    dataWorker->ref = triggerCompleteInfo_.ref;
    dataWorker->wantAgent = triggerCompleteInfo_.wantAgent;
    work->data = (void *)dataWorker;
    int ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, OnSendFinishedUvAfterWorkCallback);
    if (ret != 0) {
        delete dataWorker;
        dataWorker = nullptr;
        delete work;
        work = nullptr;
    }

    HILOG_INFO("TriggerCompleteCallBack::OnSendFinished end");
}

void JsWantAgent::Finalizer(NativeEngine* engine, void* data, void* hint)
{
    HILOG_INFO("JsWantAgent::Finalizer is called");
    std::unique_ptr<JsWantAgent>(static_cast<JsWantAgent*>(data));
}

NativeValue* JsWantAgent::Equal(NativeEngine *engine, NativeCallbackInfo *info)
{
    JsWantAgent *me = CheckParamsAndGetThis<JsWantAgent>(engine, info);
    return (me != nullptr) ? me->OnEqual(*engine, *info) : nullptr;
};

NativeValue* JsWantAgent::GetWant(NativeEngine *engine, NativeCallbackInfo *info)
{
    JsWantAgent *me = CheckParamsAndGetThis<JsWantAgent>(engine, info);
    return (me != nullptr) ? me->OnGetWant(*engine, *info) : nullptr;
};

NativeValue* JsWantAgent::GetOperationType(NativeEngine *engine, NativeCallbackInfo *info)
{
    JsWantAgent *me = CheckParamsAndGetThis<JsWantAgent>(engine, info);
    return (me != nullptr) ? me->OnGetOperationType(*engine, *info) : nullptr;
};

NativeValue* JsWantAgent::GetBundleName(NativeEngine *engine, NativeCallbackInfo *info)
{
    JsWantAgent *me = CheckParamsAndGetThis<JsWantAgent>(engine, info);
    return (me != nullptr) ? me->OnGetBundleName(*engine, *info) : nullptr;
};

NativeValue* JsWantAgent::GetUid(NativeEngine *engine, NativeCallbackInfo *info)
{
    JsWantAgent *me = CheckParamsAndGetThis<JsWantAgent>(engine, info);
    return (me != nullptr) ? me->OnGetUid(*engine, *info) : nullptr;
};

NativeValue* JsWantAgent::Cancel(NativeEngine *engine, NativeCallbackInfo *info)
{
    JsWantAgent *me = CheckParamsAndGetThis<JsWantAgent>(engine, info);
    return (me != nullptr) ? me->OnCancel(*engine, *info) : nullptr;
};

NativeValue* JsWantAgent::Trigger(NativeEngine *engine, NativeCallbackInfo *info)
{
    JsWantAgent *me = CheckParamsAndGetThis<JsWantAgent>(engine, info);
    return (me != nullptr) ? me->OnTrigger(*engine, *info) : nullptr;
};

NativeValue* JsWantAgent::GetWantAgent(NativeEngine* engine, NativeCallbackInfo* info)
{
    JsWantAgent *me = CheckParamsAndGetThis<JsWantAgent>(engine, info);
    return (me != nullptr) ? me->OnGetWantAgent(*engine, *info) : nullptr;
};

NativeValue* JsWantAgent::NapiGetWant(NativeEngine *engine, NativeCallbackInfo *info)
{
    JsWantAgent *me = CheckParamsAndGetThis<JsWantAgent>(engine, info);
    return (me != nullptr) ? me->OnNapiGetWant(*engine, *info) : nullptr;
};

NativeValue* JsWantAgent::NapiTrigger(NativeEngine *engine, NativeCallbackInfo *info)
{
    JsWantAgent *me = CheckParamsAndGetThis<JsWantAgent>(engine, info);
    return (me != nullptr) ? me->OnNapiTrigger(*engine, *info) : nullptr;
};


NativeValue* JsWantAgent::OnEqual(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_DEBUG("enter, argc = %{public}d", static_cast<int32_t>(info.argc));
    int32_t errCode = BUSINESS_ERROR_CODE_OK;
    WantAgent *pWantAgentFirst = nullptr;
    WantAgent *pWantAgentSecond = nullptr;
    if (info.argc < ARGC_TWO || info.argc > ARGC_THREE) {
        HILOG_ERROR("Not enough params");
        return engine.CreateUndefined();
    }

    NativeValue *lastParam = (info.argc >= ARGC_THREE) ? info.argv[INDEX_TWO] : nullptr;
    if (info.argv[0]->TypeOf() != NativeValueType::NATIVE_OBJECT) {
        HILOG_ERROR("Wrong argument type. Object expected.");
        errCode = ERR_NOT_OK;
        return RetErrMsg(engine, lastParam, errCode);
    }

    UnwrapWantAgent(engine, info.argv[0], (void **)&(pWantAgentFirst));
    if (pWantAgentFirst == nullptr) {
        HILOG_ERROR("Parse pWantAgentFirst failed");
        errCode = ERR_NOT_OK;
        return RetErrMsg(engine, lastParam, errCode);
    }

    if (info.argv[1]->TypeOf() != NativeValueType::NATIVE_OBJECT) {
        HILOG_ERROR("Wrong argument type. Object expected.");
        errCode = ERR_NOT_OK;
        return RetErrMsg(engine, lastParam, errCode);
    }

    UnwrapWantAgent(engine, info.argv[1], (void **)&(pWantAgentSecond));
    if (pWantAgentSecond == nullptr) {
        HILOG_ERROR("Parse pWantAgentSceond failed");
        errCode = ERR_NOT_OK;
        return RetErrMsg(engine, lastParam, errCode);
    }

    std::shared_ptr<WantAgent> wantAgentFirst = std::make_shared<WantAgent>(*pWantAgentFirst);
    std::shared_ptr<WantAgent> wantAgentSecond = std::make_shared<WantAgent>(*pWantAgentSecond);
    AsyncTask::CompleteCallback complete =
        [wantAgentFirst, wantAgentSecond](NativeEngine &engine, AsyncTask &task, int32_t status) {
            HILOG_DEBUG("OnEqual AsyncTask is called");
            bool ret = WantAgentHelper::JudgeEquality(wantAgentFirst, wantAgentSecond);
            task.Resolve(engine, CreateJsValue(engine, ret));
        };

    NativeValue *result = nullptr;
    AsyncTask::Schedule("JsWantAgent::OnEqual",
        engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
    return result;
}

NativeValue* JsWantAgent::OnGetWant(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_DEBUG("enter, argc = %{public}d", static_cast<int32_t>(info.argc));

    int32_t errCode = BUSINESS_ERROR_CODE_OK;
    WantAgent *pWantAgent = nullptr;
    if (info.argc > ARGC_TWO || info.argc < ARGC_ONE) {
        HILOG_ERROR("Not enough params");
        return engine.CreateUndefined();
    }

    NativeValue *lastParam = (info.argc >= ARGC_TWO) ? info.argv[INDEX_ONE] : nullptr;
    if (info.argv[0]->TypeOf() != NativeValueType::NATIVE_OBJECT) {
        HILOG_ERROR("Wrong argument type. Object expected.");
        errCode = ERR_NOT_OK;
        return RetErrMsg(engine, lastParam, errCode);
    }

    UnwrapWantAgent(engine, info.argv[0], (void **)&(pWantAgent));
    if (pWantAgent == nullptr) {
        HILOG_ERROR("Parse pWantAgent failed");
        errCode = ERR_NOT_OK;
        return RetErrMsg(engine, lastParam, errCode);
    }

    std::shared_ptr<WantAgent> wantAgent = std::make_shared<WantAgent>(*pWantAgent);
    AsyncTask::CompleteCallback complete = [wantAgent](NativeEngine &engine, AsyncTask &task, int32_t status) {
        HILOG_DEBUG("OnGetWant AsyncTask is called");
        std::shared_ptr<Want> want = WantAgentHelper::GetWant(wantAgent);
        if (want == nullptr) {
            task.Reject(engine, CreateJsError(engine, ERR_NOT_OK, "WantAgentHelper::GetWant result nullptr."));
            return;
        }
        task.Resolve(engine, CreateJsWant(engine, *(want)));
    };

    NativeValue *result = nullptr;
    AsyncTask::Schedule("JsWantAgent::OnGetWant",
        engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
    return result;
}

NativeValue* JsWantAgent::OnGetOperationType(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_DEBUG("JsWantAgent::OnGetOperationType enter, argc = %{public}d", static_cast<int32_t>(info.argc));
    int32_t errCode = BUSINESS_ERROR_CODE_OK;
    WantAgent *pWantAgent = nullptr;
    if (info.argc > ARGC_TWO || info.argc < ARGC_ONE) {
        HILOG_ERROR("Not enough params");
        return engine.CreateUndefined();
    }

    NativeValue *lastParam = (info.argc >= ARGC_TWO) ? info.argv[INDEX_ONE] : nullptr;
    if (info.argv[0]->TypeOf() != NativeValueType::NATIVE_OBJECT) {
        HILOG_ERROR("Wrong argument type. Object expected.");
        errCode = ERR_NOT_OK;
        return RetErrMsg(engine, lastParam, errCode);
    }

    UnwrapWantAgent(engine, info.argv[0], (void **)&(pWantAgent));
    if (pWantAgent == nullptr) {
        HILOG_ERROR("Parse pWantAgent failed");
        errCode = ERR_NOT_OK;
        return RetErrMsg(engine, lastParam, errCode);
    }

    std::shared_ptr<WantAgent> wantAgent = std::make_shared<WantAgent>(*pWantAgent);
    AsyncTask::CompleteCallback complete = [wantAgent](NativeEngine &engine, AsyncTask &task, int32_t status) {
        HILOG_DEBUG("OnGetOperationType AsyncTask is called");
        auto ret = WantAgentHelper::GetType(wantAgent);
        task.Resolve(engine, CreateJsValue(engine, ret));
    };

    NativeValue *result = nullptr;
    AsyncTask::Schedule("JsWantAgent::OnGetOperationType",
        engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
    return result;
}

NativeValue* JsWantAgent::OnGetBundleName(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_DEBUG("JsWantAgent::OnGetBundleName enter, argc = %{public}d", static_cast<int32_t>(info.argc));
    int32_t errCode = BUSINESS_ERROR_CODE_OK;
    WantAgent *pWantAgent = nullptr;
    if (info.argc > ARGC_TWO || info.argc < ARGC_ONE) {
        HILOG_ERROR("Not enough params");
        return engine.CreateUndefined();
    }

    NativeValue *lastParam = (info.argc >= ARGC_TWO) ? info.argv[INDEX_ONE] : nullptr;
    if (info.argv[0]->TypeOf() != NativeValueType::NATIVE_OBJECT) {
        HILOG_ERROR("Wrong argument type. Object expected.");
        errCode = ERR_NOT_OK;
        return RetErrMsg(engine, lastParam, errCode);
    }

    UnwrapWantAgent(engine, info.argv[0], (void **)&(pWantAgent));
    if (pWantAgent == nullptr) {
        HILOG_ERROR("Parse pWantAgent failed");
        errCode = ERR_NOT_OK;
        return RetErrMsg(engine, lastParam, errCode);
    }

    std::shared_ptr<WantAgent> wantAgent = std::make_shared<WantAgent>(*pWantAgent);
    AsyncTask::CompleteCallback complete = [wantAgent](NativeEngine &engine, AsyncTask &task, int32_t status) {
        HILOG_DEBUG("OnGetBundleName AsyncTask is called");
        auto ret = WantAgentHelper::GetBundleName(wantAgent);
        task.Resolve(engine, CreateJsValue(engine, ret));
    };

    NativeValue *result = nullptr;
    AsyncTask::Schedule("JsWantAgent::OnGetBundleName",
        engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
    return result;
}

NativeValue* JsWantAgent::OnGetUid(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_DEBUG("JsWantAgent::OnGetUid enter, argc = %{public}d", static_cast<int32_t>(info.argc));
    int32_t errCode = BUSINESS_ERROR_CODE_OK;
    WantAgent *pWantAgent = nullptr;
    if (info.argc > ARGC_TWO || info.argc < ARGC_ONE) {
        HILOG_ERROR("Not enough params");
        return engine.CreateUndefined();
    }

    NativeValue *lastParam = (info.argc >= ARGC_TWO) ? info.argv[INDEX_ONE] : nullptr;
    if (info.argv[0]->TypeOf() != NativeValueType::NATIVE_OBJECT) {
        HILOG_ERROR("Wrong argument type. Object expected.");
        errCode = ERR_NOT_OK;
        return RetErrMsg(engine, lastParam, errCode);
    }

    UnwrapWantAgent(engine, info.argv[0], (void **)&(pWantAgent));
    if (pWantAgent == nullptr) {
        HILOG_ERROR("Parse pWantAgent failed");
        errCode = ERR_NOT_OK;
        return RetErrMsg(engine, lastParam, errCode);
    }

    std::shared_ptr<WantAgent> wantAgent = std::make_shared<WantAgent>(*pWantAgent);
    AsyncTask::CompleteCallback complete = [wantAgent](NativeEngine &engine, AsyncTask &task, int32_t status) {
        HILOG_DEBUG("OnGetUid AsyncTask is called");
        auto ret = WantAgentHelper::GetUid(wantAgent);
        task.Resolve(engine, CreateJsValue(engine, ret));
    };

    NativeValue *result = nullptr;
    AsyncTask::Schedule("JsWantAgent::OnGetUid",
        engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
    return result;
}

NativeValue* JsWantAgent::OnCancel(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_DEBUG("%{public}s is called", __FUNCTION__);
    int32_t errCode = BUSINESS_ERROR_CODE_OK;
    WantAgent *pWantAgent = nullptr;
    if (info.argc > ARGC_TWO || info.argc < ARGC_ONE) {
        HILOG_ERROR("Not enough params");
        return engine.CreateUndefined();
    }

    NativeValue* lastParam = (info.argc >= ARGC_TWO) ? info.argv[INDEX_ONE] : nullptr;
    if (info.argv[0]->TypeOf() != NativeValueType::NATIVE_OBJECT) {
        HILOG_ERROR("Wrong argument type. Object expected.");
        errCode = ERR_NOT_OK;
        return RetErrMsg(engine, lastParam, errCode);
    }

    UnwrapWantAgent(engine, info.argv[0], (void **)&(pWantAgent));
    if (pWantAgent == nullptr) {
        HILOG_ERROR("Parse pWantAgent failed");
        errCode = ERR_NOT_OK;
        return RetErrMsg(engine, lastParam, errCode);
    }

    std::shared_ptr<WantAgent> wantAgent = std::make_shared<WantAgent>(*pWantAgent);
    AsyncTask::CompleteCallback complete =
        [wantAgent](NativeEngine &engine, AsyncTask &task, int32_t status) {
            HILOG_DEBUG("OnCancel AsyncTask is called");
            WantAgentHelper::Cancel(wantAgent);
            task.Resolve(engine, engine.CreateUndefined());
        };


    NativeValue* result = nullptr;
    AsyncTask::Schedule("JsWantAgent::OnCancel",
        engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
    return result;
}

NativeValue* JsWantAgent::OnTrigger(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_DEBUG("%{public}s is called", __FUNCTION__);
    if (info.argc != ARGC_THREE) {
        HILOG_ERROR("Not enough params");
        return engine.CreateUndefined();
    }

    std::shared_ptr<WantAgent> wantAgent = nullptr;
    TriggerInfo triggerInfo;
    auto triggerObj = std::make_shared<TriggerCompleteCallBack>();
    int32_t errCode = UnWrapTriggerInfoParam(engine, info, wantAgent, triggerInfo, triggerObj);
    if (errCode != BUSINESS_ERROR_CODE_OK) {
        return RetErrMsg(engine, info.argv[ARGC_TWO], errCode);
    }

    WantAgentHelper::TriggerWantAgent(wantAgent, triggerObj, triggerInfo);
    return engine.CreateNull();
}

int32_t JsWantAgent::UnWrapTriggerInfoParam(NativeEngine &engine, NativeCallbackInfo &info,
    std::shared_ptr<WantAgent> &wantAgent, TriggerInfo &triggerInfo,
    std::shared_ptr<TriggerCompleteCallBack> &triggerObj)
{
    if (info.argc != ARGC_THREE) {
        HILOG_ERROR("Not enough params");
        return ERR_NOT_OK;
    }
    auto env = reinterpret_cast<napi_env>(&engine);

    if (info.argv[ARGC_ZERO]->TypeOf() != NativeValueType::NATIVE_OBJECT) {
        HILOG_ERROR("Wrong argument type. Object expected.");
        return ERR_NOT_OK;
    }
    WantAgent *pWantAgent = nullptr;
    UnwrapWantAgent(engine, info.argv[ARGC_ZERO], (void **)&(pWantAgent));

    if (pWantAgent == nullptr) {
        HILOG_ERROR("Parse pWantAgent failed");
        return ERR_NOT_OK;
    }
    wantAgent = std::make_shared<WantAgent>(*pWantAgent);

    int32_t ret = GetTriggerInfo(engine, info.argv[ARGC_ONE], triggerInfo);
    if (ret != BUSINESS_ERROR_CODE_OK) {
        HILOG_ERROR("Get trigger info error");
        return ret;
    }

    napi_ref callback[2] = {0};
    napi_create_reference(env, reinterpret_cast<napi_value>(info.argv[ARGC_TWO]), 1, &callback[0]);
    triggerObj->SetCallbackInfo(env, callback[0]);
    triggerObj->SetWantAgentInstance(wantAgent);

    return BUSINESS_ERROR_CODE_OK;
}

int32_t JsWantAgent::GetTriggerInfo(NativeEngine &engine, NativeValue *param, TriggerInfo &triggerInfo)
{
    HILOG_DEBUG("GetTriggerInfo called.");
    if (param->TypeOf() != NativeValueType::NATIVE_OBJECT) {
        HILOG_ERROR("param type mismatch!");
        return ERR_NOT_OK;
    }

    NativeObject *objectParam = ConvertNativeValueTo<NativeObject>(param);

    int32_t code = -1;
    NativeValue *jsCode = objectParam->GetProperty("code");
    if (!ConvertFromJsValue(engine, jsCode, code)) {
        return ERR_NOT_OK;
    }

    NativeValue *jsWant = objectParam->GetProperty("want");
    std::shared_ptr<AAFwk::Want> want = nullptr;
    if (jsWant != nullptr) {
        want = std::make_shared<AAFwk::Want>();
        if (!UnwrapWant(reinterpret_cast<napi_env>(&engine), reinterpret_cast<napi_value>(jsWant), *want)) {
            return ERR_NOT_OK;
        }
    }

    std::string permission = "";
    NativeValue *jsPermission = objectParam->GetProperty("permission");
    if (!ConvertFromJsValue(engine, jsPermission, permission)) {
        return ERR_NOT_OK;
    }

    NativeValue *jsExtraInfo = objectParam->GetProperty("extraInfo");
    std::shared_ptr<AAFwk::WantParams> extraInfo = nullptr;
    if (jsExtraInfo != nullptr) {
        extraInfo = std::make_shared<AAFwk::WantParams>();
        if (!UnwrapWantParams(reinterpret_cast<napi_env>(&engine), reinterpret_cast<napi_value>(jsExtraInfo),
            *extraInfo)) {
            return ERR_NOT_OK;
        }
    }

    TriggerInfo triggerInfoData(permission, extraInfo, want, code);
    triggerInfo = triggerInfoData;
    return BUSINESS_ERROR_CODE_OK;
}

int32_t JsWantAgent::GetWantAgentParam(NativeEngine &engine, NativeCallbackInfo &info, WantAgentWantsParas &paras)
{
    HILOG_DEBUG("GetWantAgentParam called.");
    if (info.argv[0]->TypeOf() != NativeValueType::NATIVE_OBJECT) {
        HILOG_ERROR("param type mismatch!");
        return PARAMETER_ERROR;
    }
    NativeObject *paramObject = ConvertNativeValueTo<NativeObject>(info.argv[0]);

    NativeValue *jsWants = paramObject->GetProperty("wants");
    if (!jsWants->IsArray()) {
        HILOG_ERROR("wants is not array!");
        return PARAMETER_ERROR;
    }

    NativeArray *jsWantsArray = ConvertNativeValueTo<NativeArray>(jsWants);
    for (uint32_t i = 0; i < jsWantsArray->GetLength(); i++) {
        std::shared_ptr<AAFwk::Want> want = std::make_shared<AAFwk::Want>();
        NativeValue *jsWant = jsWantsArray->GetElement(i);
        if (!UnwrapWant(reinterpret_cast<napi_env>(&engine), reinterpret_cast<napi_value>(jsWant), *want)) {
            HILOG_ERROR("UnwrapWant failed!");
            return PARAMETER_ERROR;
        }
        paras.wants.emplace_back(want);
    }

    NativeValue *jsOperationType = paramObject->GetProperty("operationType");
    if (!ConvertFromJsValue(engine, jsOperationType, paras.operationType)) {
        HILOG_ERROR("Convert operationType failed!");
        return PARAMETER_ERROR;
    }

    NativeValue *jsRequestCode = paramObject->GetProperty("requestCode");
    if (!ConvertFromJsValue(engine, jsRequestCode, paras.requestCode)) {
        HILOG_ERROR("Convert requestCode failed!");
        return PARAMETER_ERROR;
    }

    if (paramObject->HasProperty("wantAgentFlags")) {
        NativeValue *jsWantAgentFlags = paramObject->GetProperty("wantAgentFlags");
        if (!jsWantAgentFlags->IsArray()) {
            HILOG_ERROR("wantAgentFlags is not array!");
            return PARAMETER_ERROR;
        }

        NativeArray *jsWantAgentFlagsArray = ConvertNativeValueTo<NativeArray>(jsWantAgentFlags);
        for (uint32_t i = 0; i < jsWantAgentFlagsArray->GetLength(); i++) {
            NativeValue *jsWantAgentFlag = jsWantAgentFlagsArray->GetElement(i);
            if (jsWantAgentFlag->TypeOf() != NativeValueType::NATIVE_NUMBER) {
                HILOG_ERROR("WantAgentFlag type error!");
                return PARAMETER_ERROR;
            }
            int32_t wantAgentFlag = 0;
            if (!ConvertFromJsValue(engine, jsWantAgentFlag, wantAgentFlag)) {
                HILOG_ERROR("Convert WantAgentFlag failed!");
                return PARAMETER_ERROR;
            }
            paras.wantAgentFlags.emplace_back(static_cast<WantAgentConstant::Flags>(wantAgentFlag));
        }
    }

    if (paramObject->HasProperty("extraInfo")) {
        NativeValue *jsExtraInfo = paramObject->GetProperty("extraInfo");
        if (jsExtraInfo->TypeOf() != NativeValueType::NATIVE_OBJECT) {
            HILOG_ERROR("ExtraInfo type error!");
            return PARAMETER_ERROR;
        }
        if (!UnwrapWantParams(reinterpret_cast<napi_env>(&engine), reinterpret_cast<napi_value>(jsExtraInfo),
            paras.extraInfo)) {
            HILOG_ERROR("Convert extraInfo failed!");
            return PARAMETER_ERROR;
        }
    }
    return BUSINESS_ERROR_CODE_OK;
}

NativeValue* JsWantAgent::WrapWantAgent(NativeEngine &engine, const std::shared_ptr<WantAgent> &wantAgent)
{
    HILOG_DEBUG("WrapWantAgent called.");
    NativeCallback callback = [](NativeEngine *engine, NativeCallbackInfo *info) -> NativeValue* {
        return info->thisVar;
    };

    NativeValue *wantAgentClass = engine.DefineClass("WantAgentClass", callback, nullptr, nullptr, 0);
    NativeValue *result = engine.CreateInstance(wantAgentClass, nullptr, 0);

    NativeObject *nativeObject = reinterpret_cast<NativeObject*>(result->GetInterface(NativeObject::INTERFACE_ID));
    NativeFinalize nativeFinalize = [](NativeEngine* engine, void* data, void* hint) {};

    nativeObject->SetNativePointer((void *)wantAgent.get(), nativeFinalize, nullptr);
    return result;
}

void JsWantAgent::UnwrapWantAgent(NativeEngine &engine, NativeValue *jsParam, void** result)
{
    HILOG_DEBUG("UnwrapWantAgent called.");
    if (jsParam == nullptr) {
        HILOG_ERROR("UnwrapWantAgent jsParam is nullptr!");
        return;
    }

    if (jsParam->TypeOf() != NATIVE_OBJECT) {
        HILOG_ERROR("UnwrapWantAgent jsParam type error!");
        return;
    }

    NativeObject *nativeObject = reinterpret_cast<NativeObject*>(jsParam->GetInterface(NativeObject::INTERFACE_ID));
    *result = nativeObject->GetNativePointer();
}

NativeValue* JsWantAgent::OnGetWantAgent(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_DEBUG("enter, argc = %{public}d", static_cast<int32_t>(info.argc));
    if (info.argc > ARGC_TWO || info.argc < ARGC_ONE) {
        HILOG_ERROR("Not enough params");
        return engine.CreateUndefined();
    }

    NativeValue *lastParam = (info.argc >= ARGC_TWO) ? info.argv[INDEX_ONE] : nullptr;
    std::shared_ptr<WantAgentWantsParas> spParas = std::make_shared<WantAgentWantsParas>();
    uint32_t ret = GetWantAgentParam(engine, info, *spParas);
    if (ret != 0) {
        HILOG_ERROR("Failed to get wantAgent param.");
        return RetErrMsg(engine, lastParam, ret);
    }

    AsyncTask::CompleteCallback complete = [obj = this, parasobj = spParas](NativeEngine &engine,
        AsyncTask &task, int32_t status) {
        HILOG_DEBUG("OnGetWantAgent AsyncTask is called");
        std::shared_ptr<AAFwk::WantParams> extraInfo = std::make_shared<AAFwk::WantParams>(parasobj->extraInfo);
        WantAgentInfo wantAgentInfo(parasobj->requestCode,
                                    static_cast<WantAgentConstant::OperationType>(parasobj->operationType),
                                    parasobj->wantAgentFlags,
                                    parasobj->wants,
                                    extraInfo);

        auto context = OHOS::AbilityRuntime::Context::GetApplicationContext();
        std::shared_ptr<WantAgent> wantAgent = WantAgentHelper::GetWantAgent(context, wantAgentInfo);

        if (wantAgent == nullptr) {
            HILOG_INFO("GetWantAgent instance is nullptr...");
        }
        task.Resolve(engine, obj->WrapWantAgent(engine, wantAgent));
    };

    NativeValue *result = nullptr;
    AsyncTask::Schedule("JsWantAgent::OnGetWantAgent",
        engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
    return result;
}

NativeValue* JsWantAgent::OnNapiGetWant(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_DEBUG("enter, argc = %{public}d", static_cast<int32_t>(info.argc));

    WantAgent *pWantAgent = nullptr;
    if (info.argc > ARGC_TWO || info.argc < ARGC_ONE) {
        HILOG_ERROR("Not enough params");
        AbilityRuntimeErrorUtil::Throw(engine, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);
        return engine.CreateUndefined();
    }

    if (info.argv[0]->TypeOf() != NativeValueType::NATIVE_OBJECT) {
        HILOG_ERROR("Wrong argument type. Object expected.");
        AbilityRuntimeErrorUtil::Throw(engine, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);
        return engine.CreateUndefined();
    }

    UnwrapWantAgent(engine, info.argv[0], (void **)&(pWantAgent));
    if (pWantAgent == nullptr) {
        HILOG_ERROR("Parse pWantAgent failed");
        AbilityRuntimeErrorUtil::Throw(engine, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);
        return engine.CreateUndefined();
    }

    std::shared_ptr<WantAgent> wantAgent = std::make_shared<WantAgent>(*pWantAgent);
    AsyncTask::CompleteCallback complete = [wantAgent](NativeEngine &engine, AsyncTask &task, int32_t status) {
        HILOG_DEBUG("OnNapiGetWant AsyncTask is called");
        std::shared_ptr<Want> want = std::make_shared<Want>();
        ErrCode result = WantAgentHelper::GetWant(wantAgent, want);
        if (result != NO_ERROR) {
            task.Reject(engine, CreateJsError(engine, result, AbilityRuntimeErrorUtil::GetErrMessage(result)));
            return;
        }
        task.ResolveWithNoError(engine, CreateJsWant(engine, *(want)));
    };
    NativeValue *lastParam = (info.argc >= ARGC_TWO) ? info.argv[INDEX_ONE] : nullptr;
    NativeValue *result = nullptr;
    AsyncTask::Schedule("JsWantAgent::OnNapiGetWant",
        engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
    return result;
}

NativeValue* JsWantAgent::OnNapiTrigger(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_DEBUG("%{public}s is called", __FUNCTION__);
    if (info.argc != ARGC_THREE) {
        HILOG_ERROR("Not enough params");
        AbilityRuntimeErrorUtil::Throw(engine, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);
        return engine.CreateUndefined();
    }

    std::shared_ptr<WantAgent> wantAgent = nullptr;
    TriggerInfo triggerInfo;
    auto triggerObj = std::make_shared<TriggerCompleteCallBack>();
    int32_t errCode = UnWrapTriggerInfoParam(engine, info, wantAgent, triggerInfo, triggerObj);
    if (errCode != NO_ERROR) {
        AbilityRuntimeErrorUtil::Throw(engine, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);
        return engine.CreateUndefined();
    }

    WantAgentHelper::TriggerWantAgent(wantAgent, triggerObj, triggerInfo);
    return engine.CreateNull();
}

NativeValue* WantAgentFlagsInit(NativeEngine *engine)
{
    HILOG_INFO("enter");

    if (engine == nullptr) {
        HILOG_ERROR("Invalid input parameters");
        return nullptr;
    }

    NativeValue *objValue = engine->CreateObject();
    NativeObject *object = ConvertNativeValueTo<NativeObject>(objValue);

    if (object == nullptr) {
        HILOG_ERROR("Failed to get object");
        return nullptr;
    }

    object->SetProperty("ONE_TIME_FLAG", CreateJsValue(*engine, static_cast<int32_t>(NUMBER_OF_PARAMETERS_ZERO)));
    object->SetProperty("NO_BUILD_FLAG", CreateJsValue(*engine, static_cast<int32_t>(NUMBER_OF_PARAMETERS_ONE)));
    object->SetProperty("CANCEL_PRESENT_FLAG", CreateJsValue(*engine, static_cast<int32_t>(NUMBER_OF_PARAMETERS_TWO)));
    object->SetProperty("UPDATE_PRESENT_FLAG", CreateJsValue(*engine,
        static_cast<int32_t>(NUMBER_OF_PARAMETERS_THREE)));
    object->SetProperty("CONSTANT_FLAG", CreateJsValue(*engine, static_cast<int32_t>(NUMBER_OF_PARAMETERS_FOUR)));
    object->SetProperty("REPLACE_ELEMENT", CreateJsValue(*engine, static_cast<int32_t>(NUMBER_OF_PARAMETERS_FIVE)));
    object->SetProperty("REPLACE_ACTION", CreateJsValue(*engine, static_cast<int32_t>(NUMBER_OF_PARAMETERS_SIX)));
    object->SetProperty("REPLACE_URI", CreateJsValue(*engine, static_cast<int32_t>(NUMBER_OF_PARAMETERS_SEVEN)));
    object->SetProperty("REPLACE_ENTITIES", CreateJsValue(*engine, static_cast<int32_t>(NUMBER_OF_PARAMETERS_EIGHT)));
    object->SetProperty("REPLACE_BUNDLE", CreateJsValue(*engine, static_cast<int32_t>(NUMBER_OF_PARAMETERS_NINE)));

    return objValue;
}

NativeValue *WantAgentOperationTypeInit(NativeEngine *engine)
{
    HILOG_INFO("enter");

    if (engine == nullptr) {
        HILOG_ERROR("Invalid input parameters");
        return nullptr;
    }

    NativeValue *objValue = engine->CreateObject();
    NativeObject *object = ConvertNativeValueTo<NativeObject>(objValue);

    if (object == nullptr) {
        HILOG_ERROR("Failed to get object");
        return nullptr;
    }

    object->SetProperty("UNKNOWN_TYPE", CreateJsValue(*engine, static_cast<int32_t>(NUMBER_OF_PARAMETERS_ZERO)));
    object->SetProperty("START_ABILITY", CreateJsValue(*engine, static_cast<int32_t>(NUMBER_OF_PARAMETERS_ONE)));
    object->SetProperty("START_ABILITIES", CreateJsValue(*engine, static_cast<int32_t>(NUMBER_OF_PARAMETERS_TWO)));
    object->SetProperty("START_SERVICE", CreateJsValue(*engine, static_cast<int32_t>(NUMBER_OF_PARAMETERS_THREE)));
    object->SetProperty("SEND_COMMON_EVENT", CreateJsValue(*engine, static_cast<int32_t>(NUMBER_OF_PARAMETERS_FOUR)));
    object->SetProperty("START_FOREGROUND_SERVICE", CreateJsValue(*engine,
        static_cast<int32_t>(NUMBER_OF_PARAMETERS_FIVE)));

    return objValue;
}

NativeValue* JsWantAgentInit(NativeEngine* engine, NativeValue* exportObj)
{
    HILOG_DEBUG("JsWantAgentInit is called");

    if (engine == nullptr || exportObj == nullptr) {
        HILOG_ERROR("engine or exportObj null");
        return nullptr;
    }

    NativeObject* object = ConvertNativeValueTo<NativeObject>(exportObj);
    if (object == nullptr) {
        HILOG_ERROR("object null");
        return nullptr;
    }

    std::unique_ptr<JsWantAgent> jsWantAgent = std::make_unique<JsWantAgent>();
    object->SetNativePointer(jsWantAgent.release(), JsWantAgent::Finalizer, nullptr);

    object->SetProperty("WantAgentFlags", WantAgentFlagsInit(engine));
    object->SetProperty("OperationType", WantAgentOperationTypeInit(engine));

    HILOG_DEBUG("JsWantAgentInit BindNativeFunction called");
    const char *moduleName = "JsWantAgent";
    BindNativeFunction(*engine, *object, "equal", moduleName, JsWantAgent::Equal);
    BindNativeFunction(*engine, *object, "getWant", moduleName, JsWantAgent::GetWant);
    BindNativeFunction(*engine, *object, "getOperationType", moduleName, JsWantAgent::GetOperationType);
    BindNativeFunction(*engine, *object, "getBundleName", moduleName, JsWantAgent::GetBundleName);
    BindNativeFunction(*engine, *object, "getUid", moduleName, JsWantAgent::GetUid);
    BindNativeFunction(*engine, *object, "cancel", moduleName, JsWantAgent::Cancel);
    BindNativeFunction(*engine, *object, "trigger", moduleName, JsWantAgent::Trigger);
    BindNativeFunction(*engine, *object, "getWantAgent", moduleName, JsWantAgent::GetWantAgent);
    HILOG_DEBUG("JsWantAgentInit end");
    return engine->CreateUndefined();
}

napi_value GetCallbackErrorResult(napi_env env, int errCode)
{
    napi_value result = nullptr;
    napi_value eCode = nullptr;
    NAPI_CALL(env, napi_create_int32(env, errCode, &eCode));
    NAPI_CALL(env, napi_create_object(env, &result));
    NAPI_CALL(env, napi_set_named_property(env, result, "code", eCode));
    return result;
}

napi_value NapiGetNull(napi_env env)
{
    napi_value result = nullptr;
    napi_get_null(env, &result);
    return result;
}
}  // namespace OHOS
