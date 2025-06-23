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

#ifndef OHOS_ABILITY_RUNTIME_CJ_INSIGHT_INTENT_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_CJ_INSIGHT_INTENT_CONTEXT_H

#include "ffi_remote_data.h"
#include "insight_intent_context.h"
#include "want.h"
#include "want_params.h"

namespace OHOS {
namespace AbilityRuntime {
/**
 * @class CjInsightIntentContext
 * CjInsightIntentContext provides a context for insightintent to execute certain tasks.
 */
class CjInsightIntentContext : public FFI::FFIData {
public:
    explicit CjInsightIntentContext(const std::shared_ptr<InsightIntentContext>& context) : context_(context) {}
    ~CjInsightIntentContext() = default;

    /**
     * Starts a new ability. Only such ability in the same application with the caller
     * can be started.
     *
     * @param env, the napi environment.
     * @param info, the params passed from js caller.
     *
     * @return result of StartAbility.
     */
    int32_t OnStartAbility(AAFwk::Want& want);

private:
    std::weak_ptr<InsightIntentContext> context_;
};

} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_CJ_INSIGHT_INTENT_CONTEXT_H
