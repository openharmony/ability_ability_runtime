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

#ifndef OHOS_ABILITY_RUNTIME_SIMULATOR_STS_ABILITY_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_SIMULATOR_STS_ABILITY_CONTEXT_H

#include <algorithm>
#include <memory>
#include <native_engine/native_value.h>
#include "ability_context.h"
#include "configuration.h"

#include "sts_runtime.h"

class STSNativeReference;

namespace OHOS {
namespace AbilityRuntime {
class StsAbilityContext final {
public:
    explicit StsAbilityContext(const std::shared_ptr<AbilityContext> &context) : context_(context) {}
    ~StsAbilityContext() = default;

private:
    std::weak_ptr<AbilityContext> context_;
};
ani_ref CreateStsAbilityContext(ani_env* env, const std::shared_ptr<AbilityContext> &context);
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_SIMULATOR_STS_ABILITY_CONTEXT_H
