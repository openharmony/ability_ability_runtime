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

#ifndef OHOS_ABILITY_RUNTIME_ABILITY_MANAGER_XCOLLIE_H
#define OHOS_ABILITY_RUNTIME_ABILITY_MANAGER_XCOLLIE_H

#include <cstdint>
#include <string>

namespace OHOS {
namespace AbilityRuntime {
constexpr uint32_t LESS_TIME_OUT_SECONDS = 10;
constexpr uint32_t DEFAULT_TIME_OUT_SECONDS = 30;
class AbilityManagerXCollie {
public:
    AbilityManagerXCollie(const std::string &tag, uint32_t timeoutSeconds = DEFAULT_TIME_OUT_SECONDS);

    ~AbilityManagerXCollie();

    void CancelAbilityManagerXCollie();
private:
    bool isCanceled_ = false;
    int32_t id_ = -1;
};
}
}

#define XCOLLIE_TIMER_DEFAULT(TAG) AbilityRuntime::AbilityManagerXCollie XCOLLIETIMER1(TAG)
#define XCOLLIE_TIMER_LESS(TAG) \
    AbilityRuntime::AbilityManagerXCollie XCOLLIETIMER2(TAG, AbilityRuntime::LESS_TIME_OUT_SECONDS)

#endif //OHOS_ABILITY_RUNTIME_ABILITY_MANAGER_XCOLLIE_H