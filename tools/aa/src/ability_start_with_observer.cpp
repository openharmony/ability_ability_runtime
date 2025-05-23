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

#include "ability_start_with_wait_observer.h"

#include "errors.h"

namespace OHOS {
namespace AAFwk {
int32_t AbilityStartWithWaitObserver::NotifyAATerminateWait(const AbilityStartWithWaitObserverData &data)
{
    std::lock_guard<std::mutex> lock(mutex_);
    data_ = data;
    waitFlag_ = false;
    return OHOS::ERR_OK;
}

void AbilityStartWithWaitObserver::GetData(bool& waitFlag, AbilityStartWithWaitObserverData& data)
{
    std::lock_guard<std::mutex> lock(mutex_);
    data = data_;
    waitFlag = waitFlag_;
}
} // namespace AAFwk
} // namespace OHOS