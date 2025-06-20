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

#include "utils/request_id_util.h"

namespace OHOS {
namespace AbilityRuntime {
std::atomic<int32_t> RequestIdUtil::requestId_{ 1 };
int32_t RequestIdUtil::GetRequestId()
{
    int32_t id = requestId_.fetch_add(1, std::memory_order_relaxed);
    if (id == 0 || id == INT32_MAX) {
        int32_t expect = id + 1;
        requestId_.compare_exchange_strong(expect, 1);
        id = requestId_.fetch_add(1, std::memory_order_relaxed);
    }
    return id;
}
} // namespace AbilityRuntime
} // namespace OHOS