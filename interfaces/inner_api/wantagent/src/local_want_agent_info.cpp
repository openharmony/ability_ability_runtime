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

#include "local_want_agent_info.h"

namespace OHOS::AbilityRuntime::WantAgent {
LocalWantAgentInfo::LocalWantAgentInfo(int requestCode, const WantAgentConstant::OperationType &operationType,
    std::vector<std::shared_ptr<AAFwk::Want>> &wants)
{
    requestCode_ = requestCode;
    operationType_ = operationType;
    if (!wants.empty()) {
        for (auto want : wants) {
            if (want != nullptr) {
                wants_.push_back(std::make_shared<AAFwk::Want>(*want));
            }
        }
    }
}

int LocalWantAgentInfo::GetRequestCode() const
{
    return requestCode_;
}

WantAgentConstant::OperationType LocalWantAgentInfo::GetOperationType() const
{
    return operationType_;
}

std::vector<std::shared_ptr<AAFwk::Want>> LocalWantAgentInfo::GetWants() const
{
    return wants_;
}
}