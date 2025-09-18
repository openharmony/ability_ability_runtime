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

#ifndef MOCK_OHOS_ABILITY_RUNTIME_MOCK_START_SPECIFIED_PROCESS_RESPONSE_H
#define MOCK_OHOS_ABILITY_RUNTIME_MOCK_START_SPECIFIED_PROCESS_RESPONSE_H

#include "gmock/gmock.h"
#include "start_specified_ability_response_stub.h"

namespace OHOS {
namespace AppExecFwk {
class MockStartSpecifiedAbilityResponse : public StartSpecifiedAbilityResponseStub {
public:
    MockStartSpecifiedAbilityResponse() = default;
    virtual ~MockStartSpecifiedAbilityResponse() = default;
    MOCK_METHOD4(OnAcceptWantResponse, void(const AAFwk::Want &, const std::string &, int32_t, int32_t));
    MOCK_METHOD2(OnTimeoutResponse, void(int32_t, int32_t));
    MOCK_METHOD5(OnNewProcessRequestResponse, void(const std::string&, int32_t, int32_t, const std::string&, int32_t));
    MOCK_METHOD2(OnNewProcessRequestTimeoutResponse, void(int32_t, int32_t));
    MOCK_METHOD2(OnStartSpecifiedFailed, void(int32_t, int32_t));
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // MOCK_OHOS_ABILITY_RUNTIME_MOCK_START_SPECIFIED_PROCESS_RESPONSE_H
