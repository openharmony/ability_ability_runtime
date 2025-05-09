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
#include "sts_runtime.h"
#include "ets_insight_intent_context.h"

class STSNativeReference;

namespace OHOS {
namespace AppExecFwk {
    struct InsightIntentExecuteResult;
} // namespace AAFwk
namespace AbilityRuntime {
class STSRuntime;

class EtsInsightIntentExecutor final : public InsightIntentExecutor {
public:
    static std::shared_ptr<EtsInsightIntentExecutor> Create(STSRuntime& runtime);
    enum class State {
        INVALID,
        CREATED,
        INITIALIZED,
        EXECUTING,
        EXECUTATION_DONE,
        DESTROYED
    };

    explicit EtsInsightIntentExecutor(STSRuntime& runtime);
public:
    EtsInsightIntentExecutor(const EtsInsightIntentExecutor&) = delete;
    EtsInsightIntentExecutor(const EtsInsightIntentExecutor&&) = delete;
    EtsInsightIntentExecutor& operator=(const EtsInsightIntentExecutor&) = delete;
    EtsInsightIntentExecutor& operator=(const EtsInsightIntentExecutor&&) = delete;
    ~EtsInsightIntentExecutor() override;

    bool Init(const InsightIntentExecutorInfo& insightIntentInfo) override;

    bool HandleExecuteIntent(
        InsightIntentExecuteMode mode,
        const std::string& name,
        const AAFwk::WantParams& param,
        const std::shared_ptr<NativeReference>& pageLoader,
        std::unique_ptr<InsightIntentExecutorAsyncCallback> callback,
        bool& isAsync) override { return false; };

    bool HandleExecuteEtsIntent(
        InsightIntentExecuteMode mode,
        const std::string& name,
        const AAFwk::WantParams& param,
        const std::shared_ptr<STSNativeReference>& pageLoader,
        std::unique_ptr<InsightIntentExecutorAsyncCallback> callback,
        bool& isAsync);

    inline State GetState() const
    {
        return state_;
    }

private:
    static std::unique_ptr<STSNativeReference> LoadEtsCode(
        const InsightIntentExecutorInfo& insightIntentInfo,
        STSRuntime& runtime);

    ani_ref CallObjectMethod(bool withResult, const char* name, const char* signature, ...);

    static void ReplyFailed(InsightIntentExecutorAsyncCallback* callback,
        InsightIntentInnerErr innerErr = InsightIntentInnerErr::INSIGHT_INTENT_EXECUTE_REPLY_FAILED);
    static void ReplySucceeded(InsightIntentExecutorAsyncCallback* callback,
        std::shared_ptr<AppExecFwk::InsightIntentExecuteResult> resultCpp);
    void ReplyFailedInner(InsightIntentInnerErr innerErr = InsightIntentInnerErr::INSIGHT_INTENT_EXECUTE_REPLY_FAILED);
    void ReplySucceededInner(std::shared_ptr<AppExecFwk::InsightIntentExecuteResult> resultCpp);
    bool ExecuteIntentCheckError();

    bool HandleResultReturnedFromEtsFunc(ani_env *env, ani_ref result, bool isAsync);

    static bool CheckParametersUIAbilityForeground(const std::shared_ptr<STSNativeReference>& windowStage);
    bool ExecuteInsightIntentUIAbilityForeground(
        const std::string& name,
        const AAFwk::WantParams& param,
        const std::shared_ptr<STSNativeReference>& windowStage);

    static bool CheckParametersUIAbilityBackground();
    bool ExecuteInsightIntentUIAbilityBackground(
        const std::string& name,
        const AAFwk::WantParams& param);

    static bool CheckParametersUIExtension(const std::shared_ptr<STSNativeReference>& UIExtensionContentSession);
    bool ExecuteInsightIntentUIExtension(
        const std::string& name,
        const AAFwk::WantParams& param,
        const std::shared_ptr<STSNativeReference>& UIExtensionContentSession);

    static bool CheckParametersServiceExtension();
    bool ExecuteInsightIntentServiceExtension(
        const std::string& name,
        const AAFwk::WantParams& param);

    static void OnExecuteResult(ani_env *env, [[maybe_unused]]ani_object aniObj, ani_object result);

    STSRuntime& runtime_;
    State state_ = State::CREATED;
    std::unique_ptr<STSNativeReference> etsObj_ = nullptr;
    std::unique_ptr<STSNativeReference> contextObj_ = nullptr;
    std::shared_ptr<EtsInsightIntentContext> contextCpp_ = nullptr;
    std::unique_ptr<InsightIntentExecutorAsyncCallback> callback_;
    bool isAsync_ = false;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_INSIGHT_INTENT_EXECUTOR_H
