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

#ifndef UNITTEST_OHOS_MOCK_ABILITY_START_WITH_WAIT_OBSERVER_STUB_H
#define UNITTEST_OHOS_MOCK_ABILITY_START_WITH_WAIT_OBSERVER_STUB_H

#include "gmock/gmock.h"

#include "ability_start_with_wait_observer_stub.h"

namespace OHOS {
namespace AAFwk {
class MockAbilityStartWithWaitObserverStub : public AbilityStartWithWaitObserverStub {
public:
    MockAbilityStartWithWaitObserverStub() = default;
    virtual ~MockAbilityStartWithWaitObserverStub() = default;
    MOCK_METHOD1(NotifyAATerminateWait, int32_t(const AbilityStartWithWaitObserverData& data));
    MOCK_METHOD4(SendRequest, int(uint32_t, MessageParcel&, MessageParcel&, MessageOption&));
    int InvokeSendRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
    {
        code_ = code;
        return 0;
    }

    int GetCode()
    {
        return code_;
    }

private:
    int code_ = 0;
};
} // namespace AAFwk
} // namespace OHOS
#endif // UNITTEST_OHOS_MOCK_ABILITY_START_WITH_WAIT_OBSERVER_STUB_H