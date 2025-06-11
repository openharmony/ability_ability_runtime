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

#ifndef OHOS_ABILITY_RUNTIME_LOCAL_WANT_AGENT_INFO_H
#define OHOS_ABILITY_RUNTIME_LOCAL_WANT_AGENT_INFO_H

#include <vector>
#include <memory>
#include "want.h"
#include "want_agent_constant.h"

namespace OHOS::AbilityRuntime::WantAgent {
/**
 * A parametric class that contains the parameters required by WantAgentHelper CreateLocalWantAgent.
 *
 * This class is used to encapsulate parameters requestCode, operationType,
 * Wants. It is used as the input parameter for the WantAgentHelper CreateLocalWantAgent method.
 */
class LocalWantAgentInfo final : public std::enable_shared_from_this<LocalWantAgentInfo> {
public:
    /**
     * Default constructor used to create an empty LocalWantAgentInfo instance.
     */
    LocalWantAgentInfo();
    virtual ~LocalWantAgentInfo() = default;

    /**
     * A constructor used to create a LocalWantAgentInfo instance based on the input parameters.
     *
     * @param requestCode Indicates the request code to set. It is a private value defined by the user.
     * @param operationType Indicates the type of the operation to be performed by the WantAgent object.
     * For details about the value range, see WantAgentConstant.OperationType.
     * @param Wants Indicates the collection of Want objects to be used for creating the WantAgent
     * object. The number of Wants in the collection is determined by WantAgentConstant.OperationType.
     */
    LocalWantAgentInfo(int requestCode, const WantAgentConstant::OperationType &operationType,
        std::vector<std::shared_ptr<AAFwk::Want>> &wants);

    /**
     * Obtains the requestCode of the WantAgent object.
     *
     * @return Returns the requestCode of the WantAgent object.
     */
    int GetRequestCode() const;

    /**
     * Obtains the operationType of the WantAgent object.
     *
     * @return Returns the operationType of the WantAgent object.
     */
    WantAgentConstant::OperationType GetOperationType() const;

    /**
     * Obtains the collection of all Wants of the WantAgent object.
     *
     * @return Returns the collection of all Wants of the WantAgent object.
     */
    std::vector<std::shared_ptr<AAFwk::Want>> GetWants() const;

private:
    int32_t requestCode_ = 0;
    WantAgentConstant::OperationType operationType_ = WantAgentConstant::OperationType::UNKNOWN_TYPE;
    std::vector<std::shared_ptr<AAFwk::Want>> wants_ = std::vector<std::shared_ptr<AAFwk::Want>>();
};
}
#endif /* OHOS_ABILITY_RUNTIME_LOCAL_WANT_AGENT_INFO_H */