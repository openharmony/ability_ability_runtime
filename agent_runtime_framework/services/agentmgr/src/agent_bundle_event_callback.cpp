/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "agent_bundle_event_callback.h"

#include "agent_card_mgr.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AgentRuntime {

void AgentBundleEventCallback::OnReceiveEvent(const EventFwk::CommonEventData eventData)
{
    const AAFwk::Want& want = eventData.GetWant();
    // action contains the change type of haps.
    std::string action = want.GetAction();
    std::string bundleName = want.GetElement().GetBundleName();
    int32_t userId = want.GetIntParam("userId", 0);
    int32_t uid = want.GetIntParam("uid", 0);
    // verify data
    if (action.empty()) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "OnReceiveEvent failed, empty action");
        return;
    }

    if (bundleName.empty()) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "OnReceiveEvent failed, empty bundleName");
        return;
    }

    TAG_LOGI(AAFwkTag::SER_ROUTER, "bundleName:%{public}s, action:%{public}s, userId:%{public}d, uid:%{public}d",
        bundleName.c_str(), action.c_str(), userId, uid);

    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED) {
        AgentCardMgr::GetInstance().HandleBundleInstall(bundleName, userId);
        return;
    }

    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED) {
        AgentCardMgr::GetInstance().HandleBundleInstall(bundleName, userId);
        return;
    }

    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) {
        AgentCardMgr::GetInstance().HandleBundleRemove(bundleName, userId);
        return;
    }
}
} // namespace AgentRuntime
} // namespace OHOS