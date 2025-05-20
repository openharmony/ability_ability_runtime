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

#include "ets_insight_intent_driver.h"

#include "ability_business_error.h"
#include "ability_manager_client.h"
#include "event_handler.h"
#include "event_runner.h"
#include "hilog_tag_wrapper.h"
#include "insight_intent_callback_interface.h"
#include "insight_intent_host_client.h"
#include "insight_intent_execute_result.h"
#include <mutex>
#include "ani_common_execute_param.h"
#include "ani_common_execute_result.h"
#include "ani_common_util.h"
#include "sts_error_utils.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
class EtsInsightIntentExecuteCallbackClient : public InsightIntentExecuteCallbackInterface,
    public std::enable_shared_from_this<EtsInsightIntentExecuteCallbackClient> {
public:
    EtsInsightIntentExecuteCallbackClient(ani_vm *vm, ani_ref callbackRef, ani_ref promiseRef)
        : vm_(vm), callbackRef_(callbackRef), promiseRef_(promiseRef) {}

    virtual ~EtsInsightIntentExecuteCallbackClient()
    {
        ani_env *env = AttachCurrentThread();
        if (env != nullptr) {
            if (promiseRef_) {
                env->GlobalReference_Delete(promiseRef_);
                promiseRef_ = nullptr;
            }
            if (callbackRef_) {
                env->GlobalReference_Delete(callbackRef_);
                callbackRef_ = nullptr;
            }
            DetachCurrentThread();
        }
    }

    void ProcessInsightIntentExecute(int32_t resultCode,
        AppExecFwk::InsightIntentExecuteResult executeResult) override
    {
        ani_env *env = AttachCurrentThread();
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::INTENT, "GetEnv failed");
            return;
        }

        ani_object error;
        ani_object result;
        if (resultCode != 0) {
            error = CreateStsErrorByNativeErr(env, resultCode);
            result = CreateNullExecuteResult(env);
        } else {
            error = CreateStsError(env, AbilityErrorCode::ERROR_OK);
            result = WrapExecuteResult(env, executeResult);
        }
        if (callbackRef_) {
            AsyncCallback(env, static_cast<ani_object>(callbackRef_), error, result);
        }
        if (promiseRef_) {
            AsyncCallback(env, static_cast<ani_object>(promiseRef_), error, result);
        }
        DetachCurrentThread();
    }

    ani_env *AttachCurrentThread()
    {
        ani_env *env = nullptr;
        ani_status status = ANI_ERROR;
        if ((status = vm_->GetEnv(ANI_VERSION_1, &env)) == ANI_OK) {
            return env;
        }

        ani_option interopEnabled { "--interop=disable", nullptr };
        ani_options aniArgs { 1, &interopEnabled };
        if ((status = vm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::INTENT, "status: %{public}d", status);
            return nullptr;
        }
        isAttachThread_ = true;
        return env;
    }

    void DetachCurrentThread()
    {
        if (isAttachThread_) {
            vm_->DetachCurrentThread();
            isAttachThread_ = false;
        }
    }

private:
    ani_vm *vm_ = nullptr;
    ani_ref callbackRef_ = nullptr;
    ani_ref promiseRef_ = nullptr;
    bool isAttachThread_ = false;
};

class EtsInsightIntentDriver {
public:
    EtsInsightIntentDriver() = default;
    ~EtsInsightIntentDriver() = default;

    static void OnExecute(ani_env *env, ani_object exparam, ani_object callback, ani_boolean isCallback)
    {
        TAG_LOGD(AAFwkTag::INTENT, "OnExecute called");
        ani_object error;
        if (exparam == nullptr) {
            TAG_LOGE(AAFwkTag::INTENT, "invalid param");
            error = CreateStsInvalidParamError(env, "invalid param");
            AsyncCallback(env, callback, error, CreateNullExecuteResult(env));
            return;
        }

        InsightIntentExecuteParam param;
        if (!UnwrapExecuteParam(env, exparam, param)) {
            TAG_LOGE(AAFwkTag::INTENT, "parse execute param failed");
            error = CreateStsInvalidParamError(env,
                "Parameter error: Parse param failed, param must be a ExecuteParam.");
            AsyncCallback(env, callback, error, CreateNullExecuteResult(env));
            return;
        }

        ani_ref callbackRef = nullptr;
        if (env->GlobalReference_Create(callback, &callbackRef) != ANI_OK) {
            TAG_LOGE(AAFwkTag::INTENT, "GlobalReference_Create failed");
            error = CreateStsErrorByNativeErr(env, static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER));
            AsyncCallback(env, callback, error, CreateNullExecuteResult(env));
            return;
        }

        ani_vm *vm = nullptr;
        if (env->GetVM(&vm) != ANI_OK) {
            TAG_LOGE(AAFwkTag::INTENT, "GetVM failed");
            error = CreateStsErrorByNativeErr(env, static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER));
            AsyncCallback(env, callback, error, CreateNullExecuteResult(env));
            return;
        }

        std::shared_ptr<EtsInsightIntentExecuteCallbackClient> client;
        if (isCallback) {
            client = std::make_shared<EtsInsightIntentExecuteCallbackClient>(vm, callbackRef, nullptr);
        } else {
            client = std::make_shared<EtsInsightIntentExecuteCallbackClient>(vm, nullptr, callbackRef);
        }
        uint64_t key = InsightIntentHostClient::GetInstance()->AddInsightIntentExecute(client);
        auto err = AbilityManagerClient::GetInstance()->ExecuteIntent(key,
            InsightIntentHostClient::GetInstance(), param);
        if (err != 0) {
            error = CreateStsErrorByNativeErr(env, err);
            AsyncCallback(env, callback, error, CreateNullExecuteResult(env));
            InsightIntentHostClient::GetInstance()->RemoveInsightIntentExecute(key);
        }
        return;
    }
};

void EtsInsightIntentDriverInit(ani_env *env)
{
    TAG_LOGD(AAFwkTag::INTENT, "EtsInsightIntentDriverInit called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null env");
        return;
    }

    ani_namespace ns;
    ani_status status = env->FindNamespace("L@ohos/app/ability/insightIntentDriver/insightIntentDriver;", &ns);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "FindNamespace insightIntentDriver failed status: %{public}d", status);
        return;
    }

    std::array kitFunctions = {
        ani_native_function {"nativeExecuteSync", nullptr,
            reinterpret_cast<void *>(EtsInsightIntentDriver::OnExecute)},
    };

    status = env->Namespace_BindNativeFunctions(ns, kitFunctions.data(), kitFunctions.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "bind nativeExecuteSync failed status: %{public}d", status);
    }
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGD(AAFwkTag::INTENT, "ANI_Constructor");
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        TAG_LOGD(AAFwkTag::INTENT, "GetEnv failed status: %{public}d", status);
        return ANI_NOT_FOUND;
    }

    EtsInsightIntentDriverInit(env);
    *result = ANI_VERSION_1;
    TAG_LOGD(AAFwkTag::INTENT, "ANI_Constructor finish");
    return ANI_OK;
}
}
} // namespace AbilityRuntime
} // namespace OHOS
