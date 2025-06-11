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

#include <gtest/gtest.h>
#include "element_name.h"

using namespace testing::ext;
namespace OHOS::AbilityRuntime::WantAgent {
/*
 * @tc.number    : LocalWantAgentInfo_0100
 * @tc.name      : LocalWantAgentInfo Constructor1
 * @tc.desc      : LocalWantAgentInfo Constructor1
 */
HWTEST(LocalWantAgentInfoTest, LocalWantAgentInfo_0100, Function | MediumTest | Level1)
{
    std::vector<std::shared_ptr<AAFwk::Want>> wants;
    LocalWantAgentInfo info = LocalWantAgentInfo(100, WantAgentConstant::OperationType::START_ABILITY, wants);
    ASSERT_EQ(info.GetRequestCode(), 100);
    ASSERT_TRUE(info.GetOperationType() == WantAgentConstant::OperationType::START_ABILITY);
    ASSERT_TRUE(info.GetWants().empty());
}

/*
 * @tc.number    : LocalWantAgentInfo_0200
 * @tc.name      : LocalWantAgentInfo Constructor2
 * @tc.desc      : LocalWantAgentInfo Constructor2
 */
HWTEST(LocalWantAgentInfoTest, LocalWantAgentInfo_0200, Function | MediumTest | Level1)
{
    std::vector<std::shared_ptr<AAFwk::Want>> wants;
    std::shared_ptr<AAFwk::Want> want1 = std::make_shared<AAFwk::Want>();
    want1->SetElement(AppExecFwk::ElementName("deviceId1", "bundleName1", "abilityName1"));
    wants.emplace_back(want1);
    std::shared_ptr<AAFwk::Want> want2 = nullptr;
    wants.emplace_back(want2);
    std::shared_ptr<AAFwk::Want> want3 = std::make_shared<AAFwk::Want>();
    want3->SetElement(AppExecFwk::ElementName("deviceId3", "bundleName3", "abilityName3"));
    wants.emplace_back(want3);

    LocalWantAgentInfo info = LocalWantAgentInfo(200, WantAgentConstant::OperationType::START_ABILITY, wants);
    ASSERT_EQ(info.GetWants().size(), 2);
    const auto actualWants = info.GetWants();
    ASSERT_EQ(actualWants[0]->GetElement().GetBundleName(), want1->GetElement().GetBundleName());
    ASSERT_EQ(actualWants[1]->GetElement().GetBundleName(), want3->GetElement().GetBundleName());
}
}