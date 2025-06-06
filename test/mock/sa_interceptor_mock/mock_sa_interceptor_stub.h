/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"),
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

#ifndef PREPARE_MOCK_SA_INTERCEPTOR_H
#define PREPARE_MOCK_SA_INTERCEPTOR_H

#include "rule.h"
#include "sa_interceptor_stub.h"

namespace OHOS {
namespace AbilityRuntime {
constexpr int32_t TYPE_NOT_ALLOW = 1;
constexpr int32_t TYPE_USER_SELECTION = 2;

class MockSAInterceptorStub : public SAInterceptorStub {
public:
    MockSAInterceptorStub(int type) : type_(type) {}
    ~MockSAInterceptorStub() {}
    int32_t OnCheckStarting(const std::string &params, Rule &rule) override
    {
        switch (type_) {
            case TYPE_NOT_ALLOW : {
                rule.type = RuleType::NOT_ALLOW;
                break;
            }
            case TYPE_USER_SELECTION : {
                rule.type = RuleType::USER_SELECTION;
                break;
            }
            default:
                break;
        }
        return 0;
    }
private:
    int type_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // PREPARE_MOCK_SA_INTERCEPTOR_H