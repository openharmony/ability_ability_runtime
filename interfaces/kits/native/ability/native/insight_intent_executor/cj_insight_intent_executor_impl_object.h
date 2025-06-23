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

#ifndef OHOS_ABILITY_RUNTIME_CJ_INSIGHT_INTENT_EXECUTOR_IMPL_OBJECT_H
#define OHOS_ABILITY_RUNTIME_CJ_INSIGHT_INTENT_EXECUTOR_IMPL_OBJECT_H

#include "cj_insight_intent_executor_info.h"
#include "configuration.h"
#include "want.h"

#ifdef WINDOWS_PLATFORM
#define CJ_EXPORT __declspec(dllexport)
#else
#define CJ_EXPORT __attribute__((visibility("default")))
#endif

namespace OHOS::Rosen {
class CJWindowStageImpl;
}

namespace OHOS {
namespace AbilityRuntime {

using CJInsightIntentExecutorHandle = void*;

/**
 * @brief cj insightIntentExecutor object.
 */
class CJInsightIntentExecutorImplObj {
public:
    CJInsightIntentExecutorImplObj() : cjID_(0) {}
    ~CJInsightIntentExecutorImplObj() = default;

    int32_t Init(const std::string& abilityName, CJInsightIntentExecutorHandle executorHandle);
    void Destroy();
    int64_t GetID() const
    {
        return cjID_;
    }

    CJExecuteResult OnExecuteInUIAbilityForegroundMode(
        const std::string& name, const AAFwk::WantParams& wantParams, OHOS::Rosen::CJWindowStageImpl* cjWindowStage);

    CJExecuteResult OnExecuteInUIAbilityBackgroundMode(const std::string& name, const AAFwk::WantParams& wantParams);

    CJExecuteResult OnExecuteInsightIntentUIExtension(
        const std::string& name, const AAFwk::WantParams& wantParams, int64_t sessionId);

    void FreeCJExecuteResult(CJExecuteResult result);

protected:
    int64_t cjID_;
};

} // namespace AbilityRuntime
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_CJ_INSIGHT_INTENT_EXECUTOR_IMPL_OBJECT_H
