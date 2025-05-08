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

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AAFwk {
namespace {
constexpr int64_t MAX_MILLISECONDS = 500;
}

RecordCostTimeUtil::RecordCostTimeUtil(const std::string &name)
    : funcName_(name), timeStart_(std::chrono::steady_clock::now())
{}

RecordCostTimeUtil::~RecordCostTimeUtil()
{
    auto costTime =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - timeStart_);
    if (costTime > std::chrono::milliseconds(MAX_MILLISECONDS)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "a_cost_time:%{public}s, name:%{public}s",
            std::to_string(costTime.count()).c_str(), funcName_.c_str());
    }
}
}  // namespace AAFwk
}  // namespace OHOS
