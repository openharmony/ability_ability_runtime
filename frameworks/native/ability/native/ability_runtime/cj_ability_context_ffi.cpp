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

#include "cj_common_ffi.h"
#include "cj_lambda.h"
#include "cj_utils_ffi.h"
#include "cj_ability_context.h"
#include "cj_want_ffi.h"
#include "ffi_remote_data.h"
#include "hilog_tag_wrapper.h"
#include "remote_object_impl.h"
#include "ability_business_error.h"
#include "ability_runtime/cj_caller_complex.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr int32_t CALLER_TIME_OUT = 10; // 10s
} // namespace


class StartAbilityByCallParameters {
public:
    int err = 0;
    sptr<IRemoteObject> remoteCallee = nullptr;
    std::shared_ptr<CallerCallBack> callerCallBack = nullptr;
    std::mutex mutexlock;
    std::condition_variable condition;
};

void GenerateCallerCallBack(std::shared_ptr<StartAbilityByCallParameters> calls,
    std::shared_ptr<CallerCallBack> callerCallBack)
{
    if (calls == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null calls");
        return;
    }
    if (callerCallBack == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null callerCallBack");
        return;
    }
    auto callBackDone = [calldata = calls] (const sptr<IRemoteObject> &obj) {
        TAG_LOGD(AAFwkTag::CONTEXT, "callBackDone called start");
        std::unique_lock<std::mutex> lock(calldata->mutexlock);
        calldata->remoteCallee = obj;
        calldata->condition.notify_all();
        TAG_LOGD(AAFwkTag::CONTEXT, "callBackDone called end");
    };

    auto releaseListen = [](const std::string &str) {
        TAG_LOGI(AAFwkTag::CONTEXT, "releaseListen is called %{public}s", str.c_str());
    };

    callerCallBack->SetCallBack(callBackDone);
    callerCallBack->SetOnRelease(releaseListen);
}

void StartAbilityByCallExecuteDone(std::shared_ptr<StartAbilityByCallParameters> calldata)
{
    if (calldata == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null calldata");
        return;
    }
    std::unique_lock<std::mutex> lock(calldata->mutexlock);
    if (calldata->remoteCallee != nullptr) {
        TAG_LOGI(AAFwkTag::CONTEXT, "not null callExecute callee");
        return;
    }

    if (calldata->condition.wait_for(lock, std::chrono::seconds(CALLER_TIME_OUT)) == std::cv_status::timeout) {
        TAG_LOGE(AAFwkTag::CONTEXT, "callExecute waiting callee timeout");
        calldata->err = -1;
    }
    TAG_LOGD(AAFwkTag::CONTEXT, "end");
}

int32_t StartAbilityByCallComplete(std::shared_ptr<AbilityContext> abilityContext,
    std::shared_ptr<StartAbilityByCallParameters> calldata, std::shared_ptr<CallerCallBack> callerCallBack,
    int64_t* callerId, int64_t* remoteId)
{
    if (calldata == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null calldata");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER);
    }
    if (calldata->err != 0) {
        TAG_LOGE(AAFwkTag::CONTEXT, "err: %{public}d", calldata->err);
        TAG_LOGD(AAFwkTag::CONTEXT, "clear failed call of startup is called");
        abilityContext->ClearFailedCallConnection(callerCallBack);
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER);
    }
    if (abilityContext == nullptr || callerCallBack == nullptr || calldata->remoteCallee == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null callComplete params error %{public}s",
            abilityContext == nullptr ? "context"
                : (calldata->remoteCallee == nullptr ? "remoteCallee" : "callerCallBack"));
        TAG_LOGD(AAFwkTag::CONTEXT, "callComplete end");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER);
    }
    auto releaseCallAbilityFunc = [abilityContext] (const std::shared_ptr<CallerCallBack> &callback) -> ErrCode {
        auto contextForRelease = abilityContext;
        if (contextForRelease == nullptr) {
            TAG_LOGE(AAFwkTag::CONTEXT, "null releaseCallAbilityFunction");
            return -1;
        }
        return contextForRelease->ReleaseCall(callback);
    };
    return CreateCjCallerComplex(releaseCallAbilityFunc, calldata->remoteCallee,
        callerCallBack, callerId, remoteId);
}

extern "C" {
CJ_EXPORT int32_t FFIAbilityContextStartAbilityByCall(int64_t id, WantHandle wantHandle,
    int64_t* callerId, int64_t* remoteId)
{
    if (callerId == nullptr) {
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER);
    }
    auto context = FFIData::GetData<CJAbilityContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null CJAbilityContext");
        return ERR_INVALID_INSTANCE_CODE;
    }
    int32_t userId = DEFAULT_INVAL_VALUE;
    AAFwk::Want* want = reinterpret_cast<AAFwk::Want*>(wantHandle);
    if (want == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null wantHandle");
        return ERR_INVALID_INSTANCE_CODE;
    }
    std::shared_ptr<StartAbilityByCallParameters> calls = std::make_shared<StartAbilityByCallParameters>();
    auto callerCallBack = std::make_shared<CallerCallBack>();
    if (calls == nullptr || callerCallBack == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null callerCallBack or calls");
        return ERR_INVALID_INSTANCE_CODE;
    }
    GenerateCallerCallBack(calls, callerCallBack);
    auto ret = context->StartAbilityByCall(*want, callerCallBack, userId);
    if (ret != 0) {
        TAG_LOGE(AAFwkTag::CONTEXT, "startAbility failed");
        return static_cast<int32_t>(GetJsErrorCodeByNativeError(ret));
    }
    if (calls->remoteCallee == nullptr) {
        TAG_LOGI(AAFwkTag::CONTEXT, "null remoteCallee");
        StartAbilityByCallExecuteDone(calls);
    }
    return StartAbilityByCallComplete(context->GetAbilityContext(), calls, callerCallBack, callerId, remoteId);
}
}
} // namespace AbilityRuntime
} // namespace OHOS
