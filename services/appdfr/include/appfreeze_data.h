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
#ifndef OHOS_ABILITY_RUNTIME_APPFREEZE_DATA_H
#define OHOS_ABILITY_RUNTIME_APPFREEZE_DATA_H

#include <map>

namespace OHOS {
namespace AppExecFwk {
struct CpuFreqData {
    uint64_t frequency;
    uint64_t runningTime;
};

struct FrequencyPair {
    uint64_t frequency;
    float percentage;
};

struct TotalTime {
    uint64_t totalRunningTime;
    uint64_t totalCpuTime;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_APPFREEZE_DATA_H
