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

#ifndef UNITTEST_OHOS_AGENT_RUNTIME_AGENT_CONNECTOR_STUB_TEST_MOCK_H
#define UNITTEST_OHOS_AGENT_RUNTIME_AGENT_CONNECTOR_STUB_TEST_MOCK_H

#define private public
#include "agent_connector_stub.h"
#undef private

#include <gmock/gmock.h>
#include <iremote_object.h>
#include <iremote_stub.h>
#include "ipc_types.h"

namespace OHOS {
namespace AgentRuntime {

class AgentConnectorStubTestMock : public AgentConnectorStub {
public:
    AgentConnectorStubTestMock() = default;
    virtual ~AgentConnectorStubTestMock() = default;

    int32_t SendData(const std::string &data) override
    {
        return 0;
    }

    int32_t Authorize(const std::string &data) override
    {
        return 0;
    }
};

} // namespace AgentRuntime
} // namespace OHOS

#endif // UNITTEST_OHOS_AGENT_RUNTIME_AGENT_CONNECTOR_STUB_TEST_MOCK_H
