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

#include "ets_insight_intent_provider.h"

#include "ability_business_error.h"
#include "hilog_tag_wrapper.h"
#include "insight_intent_execute_result.h"
#include "ani_common_execute_result.h"
#include "ani_common_util.h"
#include "ets_error_utils.h"
#include "insight_intent_delay_result_callback_mgr.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
namespace {
constexpr const char *INSIGHT_INTENT_PROVIDER_CLASS_NAME =
    "L@ohos/app/ability/insightIntentProvider/insightIntentProvider;";
}

class EtsInsightIntentProvider {
public:
    EtsInsightIntentProvider() = default;
    ~EtsInsightIntentProvider() = default;

    static void OnSendExecuteResult(ani_env *env, ani_int intentId, ani_object aniResult, ani_object callback)
    {
        TAG_LOGD(AAFwkTag::INTENT, "OnSendExecuteResult called");
        auto nativeResult = std::make_shared<AppExecFwk::InsightIntentExecuteResult>();
        ani_object errorObject = nullptr;
        if (!UnwrapExecuteResult(env, aniResult, *nativeResult)) {
            TAG_LOGE(AAFwkTag::INTENT, " failed to UnwrapExecuteResult");
            errorObject = EtsErrorUtil::CreateErrorByNativeErr(env,
                static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER));
        }
        auto errCode = InsightIntentDelayResultCallbackMgr::GetInstance().HandleExecuteDone(intentId, *nativeResult);
        errorObject = EtsErrorUtil::CreateError(env, static_cast<AbilityErrorCode>(errCode));
        AppExecFwk::AsyncCallback(env, callback, errorObject, nullptr);
    }
};

void EtsInsightIntentProviderInit(ani_env *env)
{
    TAG_LOGD(AAFwkTag::INTENT, "EtsInsightIntentProviderInit called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null env");
        return;
    }

    ani_namespace ns;
    ani_status status = env->FindNamespace(INSIGHT_INTENT_PROVIDER_CLASS_NAME, &ns);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "FindNamespace insightIntentProvider failed status: %{public}d", status);
        return;
    }

    std::array nativeFunctions = {
        ani_native_function {"nativeSendExecuteResult", nullptr,
            reinterpret_cast<void *>(EtsInsightIntentProvider::OnSendExecuteResult)},
    };

    status = env->Namespace_BindNativeFunctions(ns, nativeFunctions.data(), nativeFunctions.size());
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

    EtsInsightIntentProviderInit(env);
    *result = ANI_VERSION_1;
    TAG_LOGD(AAFwkTag::INTENT, "ANI_Constructor finish");
    return ANI_OK;
}
}
} // namespace AbilityRuntime
} // namespace OHOS
