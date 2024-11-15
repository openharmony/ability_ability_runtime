/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "ability_manager_service.h"
#include "main_element_utils.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AAFwk {
class MainElementUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void MainElementUtilsTest::SetUpTestCase(void)
{}
void MainElementUtilsTest::TearDownTestCase(void)
{}
void MainElementUtilsTest::SetUp()
{}
void MainElementUtilsTest::TearDown()
{}

/*
 * Feature: MainElementUtils
 * Function: CheckMainElement
 * SubFunction: NA
 * FunctionPoints:MainElementUtils CheckMainElement
 * EnvConditions: NA
 * CaseDescription: Verify CheckMainElement
 */
HWTEST_F(MainElementUtilsTest, CheckMainElement_001, TestSize.Level1)
{
    HapModuleInfo hapModuleInfo;
    std::string processName = "processName";
    std::string mainElement = "";
    bool isDataAbility = false;
    std::string uriStr;
    AbilityInfo abilityInfo;
    hapModuleInfo.mainAbility = "mainAbility";
    hapModuleInfo.isModuleJson = false;
    abilityInfo.process = "process";
    abilityInfo.name = "mainAbility";
    hapModuleInfo.abilityInfos.push_back(abilityInfo);
    bool res = MainElementUtils::CheckMainElement(hapModuleInfo,
        processName, mainElement, isDataAbility, uriStr);
    EXPECT_FALSE(res);
}

/*
 * Feature: MainElementUtils
 * Function: CheckMainElement
 * SubFunction: NA
 * FunctionPoints:MainElementUtils CheckMainElement
 * EnvConditions: NA
 * CaseDescription: Verify CheckMainElement
 */
HWTEST_F(MainElementUtilsTest, CheckMainElement_002, TestSize.Level1)
{
    HapModuleInfo hapModuleInfo;
    std::string processName = "processName";
    std::string mainElement = "";
    bool isDataAbility = false;
    std::string uriStr;
    AbilityInfo abilityInfo;
    hapModuleInfo.mainAbility = "mainAbility";
    hapModuleInfo.isModuleJson = false;
    abilityInfo.process = "processName";
    abilityInfo.name = "";
    hapModuleInfo.abilityInfos.push_back(abilityInfo);
    bool res = MainElementUtils::CheckMainElement(hapModuleInfo,
        processName, mainElement, isDataAbility, uriStr);
    EXPECT_FALSE(res);
}

/*
 * Feature: MainElementUtils
 * Function: CheckMainElement
 * SubFunction: NA
 * FunctionPoints:MainElementUtils CheckMainElement
 * EnvConditions: NA
 * CaseDescription: Verify CheckMainElement
 */
HWTEST_F(MainElementUtilsTest, CheckMainElement_003, TestSize.Level1)
{
    HapModuleInfo hapModuleInfo;
    std::string processName = "processName";
    std::string mainElement = "";
    bool isDataAbility = false;
    std::string uriStr;
    AbilityInfo abilityInfo;
    hapModuleInfo.mainAbility = "mainAbility";
    hapModuleInfo.isModuleJson = false;
    abilityInfo.process = "processName";
    abilityInfo.name = "mainAbility";
    abilityInfo.uri = "//";
    abilityInfo.type = AbilityType::DATA;
    hapModuleInfo.abilityInfos.push_back(abilityInfo);
    bool res = MainElementUtils::CheckMainElement(hapModuleInfo,
        processName, mainElement, isDataAbility, uriStr);
    EXPECT_FALSE(res);
}

/*
 * Feature: MainElementUtils
 * Function: CheckMainElement
 * SubFunction: NA
 * FunctionPoints:MainElementUtils CheckMainElement
 * EnvConditions: NA
 * CaseDescription: Verify CheckMainElement
 */
HWTEST_F(MainElementUtilsTest, CheckMainElement_004, TestSize.Level1)
{
    HapModuleInfo hapModuleInfo;
    std::string processName = "processName";
    std::string mainElement = "";
    bool isDataAbility = false;
    std::string uriStr;
    AbilityInfo abilityInfo;
    hapModuleInfo.mainAbility = "mainAbility";
    hapModuleInfo.isModuleJson = false;
    abilityInfo.process = "processName";
    abilityInfo.name = "mainAbility";
    abilityInfo.uri = "//";
    abilityInfo.type = AbilityType::PAGE;
    hapModuleInfo.abilityInfos.push_back(abilityInfo);
    bool res = MainElementUtils::CheckMainElement(hapModuleInfo,
        processName, mainElement, isDataAbility, uriStr);
    EXPECT_FALSE(res);
}

/*
 * Feature: MainElementUtils
 * Function: CheckMainElement
 * SubFunction: NA
 * FunctionPoints:MainElementUtils CheckMainElement
 * EnvConditions: NA
 * CaseDescription: Verify CheckMainElement
 */
HWTEST_F(MainElementUtilsTest, CheckMainElement_005, TestSize.Level1)
{
    HapModuleInfo hapModuleInfo;
    std::string processName = "processName";
    std::string mainElement = "";
    bool isDataAbility = false;
    std::string uriStr;
    hapModuleInfo.mainAbility = "";
    hapModuleInfo.isModuleJson = true;
    bool res = MainElementUtils::CheckMainElement(hapModuleInfo,
        processName, mainElement, isDataAbility, uriStr);
    EXPECT_FALSE(res);
}

/*
 * Feature: MainElementUtils
 * Function: CheckMainElement
 * SubFunction: NA
 * FunctionPoints:MainElementUtils CheckMainElement
 * EnvConditions: NA
 * CaseDescription: Verify CheckMainElement
 */
HWTEST_F(MainElementUtilsTest, CheckMainElement_006, TestSize.Level1)
{
    HapModuleInfo hapModuleInfo;
    std::string processName = "processName";
    std::string mainElement = "";
    bool isDataAbility = false;
    std::string uriStr;
    hapModuleInfo.mainAbility = "mainAbility";
    hapModuleInfo.isModuleJson = true;
    hapModuleInfo.process = "";
    bool res = MainElementUtils::CheckMainElement(hapModuleInfo,
        processName, mainElement, isDataAbility, uriStr);
    EXPECT_FALSE(res);
}
}  // namespace AAFwk
}  // namespace OHOS
