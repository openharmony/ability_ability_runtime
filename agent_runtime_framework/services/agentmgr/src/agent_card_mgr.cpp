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

#include "agent_card_mgr.h"

#include <unistd.h>

#include "agent_card.h"
#include "agent_card_db_mgr.h"
#include "hilog_tag_wrapper.h"
#include "json_utils.h"

namespace OHOS {
namespace AgentRuntime {
using namespace OHOS::AppExecFwk;
using json = nlohmann::json;
namespace {
const std::string AGENT_CONFIG = "ohos.extension.agent";
} // namespace
AgentCardMgr &AgentCardMgr::GetInstance()
{
    static AgentCardMgr instance;
    return instance;
}

AgentCardMgr::AgentCardMgr() {}

AgentCardMgr::~AgentCardMgr() {}

int32_t AgentCardMgr::HandleBundleInstall(const std::string &bundleName, int32_t userId)
{
    if (bundleName.empty()) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "invalid bundleName");
        return -1;
    }
    BundleInfo bundleInfo;
    bool result = bundleMgrClient_.GetBundleInfo(bundleName, BundleFlag::GET_BUNDLE_WITH_EXTENSION_INFO,
        bundleInfo, userId);
    if (!result) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "Get Bundle Info fail");
        return -1;
    }
    std::vector<AgentCard> cards;
    for (auto const &extensionInfo : bundleInfo.extensionInfos) {
        if (extensionInfo.type != ExtensionAbilityType::BACKUP) {
            continue;
        }
        std::vector<std::string> profileInfos{};
        bundleMgrClient_.GetResConfigFile(extensionInfo, AGENT_CONFIG, profileInfos);
        for (const std::string &profileInfo : profileInfos) {
            if (!json::accept(profileInfo)) {
                return -1;
            }
            json j = json::parse(profileInfo);
            if (!j.contains("agent_cards")) {
                return -1;
            }
            for (auto cardStr : j["agent_cards"]) {
                AgentCard card = AgentCard::FromJson(cardStr);
                cards.push_back(card);
            }
        }
    }
    return AgentCardDbMgr::GetInstance().InsertData(bundleName, userId, cards);
}

int32_t AgentCardMgr::HandleBundleUpdate(const std::string &bundleName, int32_t userId)
{
    return HandleBundleInstall(bundleName, userId);
}

int32_t AgentCardMgr::HandleBundleRemove(const std::string &bundleName, int32_t userId)
{
    if (bundleName.empty()) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "invalid bundleName");
        return -1;
    }
    return AgentCardDbMgr::GetInstance().DeleteData(bundleName, userId);
}
} // namespace AgentRuntime
} // namespace OHOS
