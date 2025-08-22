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

#ifndef OHOS_ABILITY_RUNTIME_ETS_INSIGHT_INTENT_EXECUTOR_H
#define OHOS_ABILITY_RUNTIME_ETS_INSIGHT_INTENT_EXECUTOR_H

#include "insight_intent_executor.h"
#include "ets_insight_intent_context.h"
#include "ets_native_reference.h"
#include "ets_runtime.h"

namespace OHOS {
namespace AppExecFwk {
struct InsightIntentExecuteResult;
} // namespace AAFwk
namespace AbilityRuntime {

class EtsInsightIntentExecutor final : public InsightIntentExecutor {
public:
    static InsightIntentExecutor *Create(Runtime &runtime);
    enum class State {
        INVALID,
        CREATED,
        INITIALIZED,
        EXECUTING,
        EXECUTATION_DONE,
        DESTROYED
    };

    explicit EtsInsightIntentExecutor(ETSRuntime &runtime);
public:
    EtsInsightIntentExecutor(const EtsInsightIntentExecutor&) = delete;
    EtsInsightIntentExecutor(const EtsInsightIntentExecutor&&) = delete;
    EtsInsightIntentExecutor &operator=(const EtsInsightIntentExecutor&) = delete;
    EtsInsightIntentExecutor &operator=(const EtsInsightIntentExecutor&&) = delete;
    ~EtsInsightIntentExecutor() override;

    bool Init(const InsightIntentExecutorInfo &insightIntentInfo) override;

    bool HandleExecuteIntent(
        std::shared_ptr<InsightIntentExecuteParam> executeParam,
        const std::shared_ptr<NativeReference> &pageLoader,
        std::unique_ptr<InsightIntentExecutorAsyncCallback> callback,
        bool &isAsync) override { return false; };
    
    bool HandleExecuteIntent(
        std::shared_ptr<InsightIntentExecuteParam> executeParam,
        void *pageLoader,
        std::unique_ptr<InsightIntentExecutorAsyncCallback> callback,
        bool &isAsync) override;

    inline State GetState() const
    {
        return state_;
    }

private:
    static std::unique_ptr<AppExecFwk::ETSNativeReference> LoadEtsCode(
        const InsightIntentExecutorInfo &insightIntentInfo,
        ETSRuntime &runtime);

    ani_ref CallObjectMethod(bool withResult, const char *name, const char *ignature, ...);

    static void ReplyFailed(InsightIntentExecutorAsyncCallback *callback,
        InsightIntentInnerErr innerErr = InsightIntentInnerErr::INSIGHT_INTENT_EXECUTE_REPLY_FAILED);
    static void ReplySucceeded(InsightIntentExecutorAsyncCallback *callback,
        std::shared_ptr<AppExecFwk::InsightIntentExecuteResult> resultCpp);
    void ReplyFailedInner(InsightIntentInnerErr innerErr = InsightIntentInnerErr::INSIGHT_INTENT_EXECUTE_REPLY_FAILED);
    void ReplySucceededInner(std::shared_ptr<AppExecFwk::InsightIntentExecuteResult> resultCpp);
    bool ExecuteIntentCheckError();

    bool HandleResultReturnedFromEtsFunc(ani_env *env, ani_ref result, bool isAsync);

    static bool CheckParametersUIAbilityForeground(ani_ref windowStage);
    bool ExecuteInsightIntentUIAbilityForeground(
        const std::string &name,
        const AAFwk::WantParams &param,
        ani_ref windowStage);

    static bool CheckParametersUIAbilityBackground();
    bool ExecuteInsightIntentUIAbilityBackground(
        const std::string &name,
        const AAFwk::WantParams &param);

    static bool CheckParametersUIExtension(ani_ref UIExtensionContentSession);
    bool ExecuteInsightIntentUIExtension(
        const std::string &name,
        const AAFwk::WantParams &param,
        ani_ref UIExtensionContentSession);

    static bool CheckParametersServiceExtension();
    bool ExecuteInsightIntentServiceExtension(
        const std::string &name,
        const AAFwk::WantParams &param);

    static void OnExecuteResult(ani_env *env, ani_object aniObj, ani_object result);

    ETSRuntime &runtime_;
    State state_ = State::CREATED;
    std::unique_ptr<AppExecFwk::ETSNativeReference> etsObj_ = nullptr;
    std::unique_ptr<AppExecFwk::ETSNativeReference> contextObj_ = nullptr;
    std::shared_ptr<EtsInsightIntentContext> contextCpp_ = nullptr;
    std::unique_ptr<InsightIntentExecutorAsyncCallback> callback_;
    bool isAsync_ = false;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_INSIGHT_INTENT_EXECUTOR_H
