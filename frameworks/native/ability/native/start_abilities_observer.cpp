/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "start_abilities_observer.h"

#include "ets_observer_instance.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {

void StartAbilitiesObserver::HandleFinished(const std::string &requestKey, int32_t resultCode)
{
    TAG_LOGI(AAFwkTag::ABILITY, "HandleFinished %{public}s, %{public}d", requestKey.c_str(), resultCode);
    ETSStartAbilitiesHandleFinished(requestKey, resultCode);
}

} // namespace AbilityRuntime
} // namespace OHOS
