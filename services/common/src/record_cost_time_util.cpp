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

#include "record_cost_time_util.h"

#include <ctime>
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AAFwk {
namespace {
constexpr int64_t MAX_MILLISECONDS = 500;
// NANOSECONDS mean 10^9 nano second
constexpr int64_t NANOSECONDS = 1000000000;
// MILLISECONDS mean 10^6 milli second
constexpr int64_t MILLISECONDS = 1000000;
}

int64_t RecordCostTimeUtil::SystemTimeMillisecond()
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)((t.tv_sec) * NANOSECONDS + t.tv_nsec) / MILLISECONDS;
}

RecordCostTimeUtil::RecordCostTimeUtil(const std::string &name) : funcName_(name)
{
    timeStart_ = SystemTimeMillisecond();
}

RecordCostTimeUtil::~RecordCostTimeUtil()
{
    int64_t costTime = SystemTimeMillisecond() - timeStart_;
    if (costTime > MAX_MILLISECONDS) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "a_cost_time:%{public}s, name:%{public}s",
            std::to_string(costTime).c_str(), funcName_.c_str());
    }
}
}  // namespace AAFwk
}  // namespace OHOS
