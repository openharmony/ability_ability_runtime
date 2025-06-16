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

#ifndef OHOS_ABILITY_RUNTIME_HITRACE_CHAIN_UTILS_H
#define OHOS_ABILITY_RUNTIME_HITRACE_CHAIN_UTILS_H

#include "hitracechain.h"

#define Ability_MANAGER_HITRACE_CHAIN_NAME(name, flag) AAFwk::AbilityHitraceChain traceid(name, flag)

namespace OHOS {
namespace AAFwk {
class AbilityHitraceChain {
public:
    AbilityHitraceChain(const std::string &name, HiTraceFlag flags);
    ~AbilityHitraceChain();

private:
    HiviewDFX::HiTraceId traceId_;
};
} // namespace AAFwk
} // namespace OHOS

#endif // #define OHOS_ABILITY_RUNTIME_HITRACE_CHAIN_UTILS_H