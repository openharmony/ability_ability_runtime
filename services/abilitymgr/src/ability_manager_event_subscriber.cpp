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

#include "ability_manager_event_subscriber.h"

#include "common_event_support.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
AbilityManagerEventSubscriber::AbilityManagerEventSubscriber(
    const EventFwk::CommonEventSubscribeInfo &subscribeInfo,
    const std::function<void()> &userScreenUnlockCallback)
    : EventFwk::CommonEventSubscriber(subscribeInfo),
    userScreenUnlockCallback_(userScreenUnlockCallback)
{}

void AbilityManagerEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    const AAFwk::Want &want = data.GetWant();
    std::string action = want.GetAction();
    TAG_LOGD(AAFwkTag::ABILITYMGR, "The action: %{public}s.", action.c_str());
    if (userScreenUnlockCallback_ == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "nullptr callback");
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED) {
        if (eventSet_.find(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED) != eventSet_.end()) {
            userScreenUnlockCallback_();
            eventSet_.clear();
        } else {
            eventSet_.insert(action);
        }
        return;
    }
    if ((action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED)) {
        if (eventSet_.find(EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED) != eventSet_.end()) {
            userScreenUnlockCallback_();
            eventSet_.clear();
        } else {
            eventSet_.insert(action);
        }
    }
}
} // namespace AbilityRuntime
} // namespace OHOS