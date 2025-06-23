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

#ifndef OHOS_ABILITY_RUNTIME_CJ_INSIGHT_INTENT_EXECUTOR_H
#define OHOS_ABILITY_RUNTIME_CJ_INSIGHT_INTENT_EXECUTOR_H

#include <memory>
#include <string>

#include "cj_insight_intent_executor_info.h"
#include "insight_intent_constant.h"
#include "insight_intent_context.h"

namespace OHOS::Rosen {
class CJWindowStageImpl;
}

namespace OHOS {
namespace AAFwk {
class WantParams;
} // namespace AAFwk
namespace AppExecFwk {
struct InsightIntentExecuteResult;
template<typename>
class AbilityTransactionCallbackInfo;
} // namespace AppExecFwk
namespace AbilityRuntime {
class Runtime;
using InsightIntentExecutorAsyncCallback =
    AppExecFwk::AbilityTransactionCallbackInfo<AppExecFwk::InsightIntentExecuteResult>;
class CJInsightIntentExecutor {
public:
    static std::shared_ptr<CJInsightIntentExecutor> Create(Runtime& runtime);

protected:
    CJInsightIntentExecutor() = default;

public:
    CJInsightIntentExecutor(const CJInsightIntentExecutor&) = delete;
    CJInsightIntentExecutor(const CJInsightIntentExecutor&&) = delete;
    CJInsightIntentExecutor& operator=(const CJInsightIntentExecutor&) = delete;
    CJInsightIntentExecutor& operator=(const CJInsightIntentExecutor&&) = delete;
    virtual ~CJInsightIntentExecutor() = default;

    /**
     * @brief Init the insight intent executor and insight intent context.
     *
     * @param
     */
    virtual bool Init(const CJInsightIntentExecutorInfo& intentInfo) = 0;

    /**
     * @brief Handling the life cycle execute insight intent.
     *
     * @param
     *
     */
    virtual bool HandleExecuteIntent(InsightIntentExecuteMode mode, const std::string& name,
        const AAFwk::WantParams& params, CJPageLoader pageLoader,
        std::unique_ptr<InsightIntentExecutorAsyncCallback> callback) = 0;

    /**
     * @brief Get current insight intent context.
     *
     * @return std::shared_ptr<InsightIntentContext>
     */
    std::shared_ptr<InsightIntentContext> GetContext();

private:
    std::shared_ptr<InsightIntentContext> context_ = nullptr;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_CJ_RUNTIME_INSIGHT_INTENT_EXECUTOR_H
