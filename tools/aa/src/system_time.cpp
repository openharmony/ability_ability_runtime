/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "system_time.h"

#include "hilog_tag_wrapper.h"
#include "inner_event.h"

namespace OHOS {
namespace AAFwk {
using namespace OHOS::AppExecFwk;

int64_t SystemTime::GetNowSysTime()
{
    TAG_LOGI(AAFwkTag::AA_TOOL, "enter");

    InnerEvent::TimePoint nowSys = InnerEvent::Clock::now();
    auto epoch = nowSys.time_since_epoch();
    auto value = std::chrono::duration_cast<std::chrono::milliseconds>(epoch);
    int64_t duration = value.count();

    return duration;
}
}  // namespace AAFwk
}  // namespace OHOS
