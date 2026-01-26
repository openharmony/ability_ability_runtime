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

#ifndef OHOS_AGENT_RUNTIME_AGENT_MANAGER_CLIENT_H
#define OHOS_AGENT_RUNTIME_AGENT_MANAGER_CLIENT_H

#include <condition_variable>
#include <functional>
#include <memory>

#include "iagent_manager.h"

namespace OHOS {
namespace AgentRuntime {
using ClearProxyCallback = std::function<void(const wptr<IRemoteObject>&)>;

class AgentManagerClient final : public std::enable_shared_from_this<AgentManagerClient> {
public:
    AgentManagerClient() = default;
    virtual ~AgentManagerClient() = default;
    static AgentManagerClient &GetInstance();

    void OnLoadSystemAbilitySuccess(const sptr<IRemoteObject> &remoteObject);
    void OnLoadSystemAbilityFail();

    int32_t GetAllAgentCards(std::vector<AgentCard> &cards);
    int32_t GetAgentCardsByBundleName(const std::string &bundleName, std::vector<AgentCard> &cards);
    int32_t GetAgentCardByAgentId(const std::string &bundleName, const std::string &agentId, AgentCard &card);

private:
    sptr<IAgentManager> GetAgentMgrProxy();
    void ClearProxy();
    bool LoadAgentMgrService();
    void SetAgentMgr(const sptr<IRemoteObject> &remoteObject);
    sptr<IAgentManager> GetAgentMgr();

    class AgentManagerServiceDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit AgentManagerServiceDeathRecipient(const ClearProxyCallback &proxy) : proxy_(proxy) {}
        virtual ~AgentManagerServiceDeathRecipient() = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;

    private:
        ClearProxyCallback proxy_;
    };

private:
    std::condition_variable loadSaCondition_;
    std::mutex loadSaMutex_;
    bool loadSaFinished_;
    std::mutex mutex_;
    sptr<IAgentManager> agentMgr_ = nullptr;
};
} // namespace AgentRuntime
} // namespace OHOS
#endif // OHOS_AGENT_RUNTIME_AGENT_MANAGER_CLIENT_H
