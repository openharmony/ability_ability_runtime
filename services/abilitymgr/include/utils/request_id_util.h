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

#ifndef OHOS_ABILITY_RUNTIME_REQUEST_ID_UTIL_H
#define OHOS_ABILITY_RUNTIME_REQUEST_ID_UTIL_H

#include <atomic>
#include <climits>

namespace OHOS {
namespace AbilityRuntime {
class RequestIdUtil {
public:
    static int32_t GetRequestId();

private:
    static std::atomic<int32_t> requestId_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_REQUEST_ID_UTIL_H