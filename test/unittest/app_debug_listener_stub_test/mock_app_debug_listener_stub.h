/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_MOCK_APP_DEBUG_LISTENER_STUB_H
#define OHOS_ABILITY_RUNTIME_MOCK_APP_DEBUG_LISTENER_STUB_H

#include <gmock/gmock.h>
#define private public
#include "app_debug_listener_stub.h"
#undef private
namespace OHOS {
namespace AppExecFwk {
class MockAppDebugListenerStub : public AppDebugListenerStub {
public:
    MockAppDebugListenerStub() {}
    virtual ~ MockAppDebugListenerStub() {}
    MOCK_METHOD1(OnAppDebugStarted, void(const std::vector<AppDebugInfo> &debugInfos));
    MOCK_METHOD1(OnAppDebugStoped, void(const std::vector<AppDebugInfo> &debugInfos));
};
} // namespace AAFwk
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_MOCK_APP_DEBUG_LISTENER_STUB_H