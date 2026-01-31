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

#ifndef OHOS_AGENT_RUNTIME_AGENT_EXTENSION_INTERFACE_H
#define OHOS_AGENT_RUNTIME_AGENT_EXTENSION_INTERFACE_H

#include <iremote_broker.h>
#include "want.h"

namespace OHOS {
namespace AgentRuntime {
class IAgentExtension : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.aafwk.IAgentExtension");

    /**
     * SendData, send the data to agent extension
     *
     * @param data, the data which is sent
     */
    virtual int32_t SendData(sptr<IRemoteObject> hostProxy, std::string &data) = 0;

    enum {
        SEND_DATA = 1,
    };
};
}  // namespace AgentRuntime
}  // namespace OHOS
#endif  // OHOS_AGENT_RUNTIME_AGENT_EXTENSION_INTERFACE_H
