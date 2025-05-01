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

/*
 * Feature: MainElementUtils
 * Function: CheckMainUIAbility
 * SubFunction: NA
 * FunctionPoints:MainElementUtils CheckMainUIAbility
 * EnvConditions: NA
 * CaseDescription: Verify CheckMainUIAbility
 */
HWTEST_F(MainElementUtilsTest, CheckMainUIAbility_001, TestSize.Level1)
{
    AppExecFwk::BundleInfo bundleInfo;
    std::vector<HapModuleInfo> hapModuleInfos;
    HapModuleInfo moduleInfo;
    moduleInfo.name = "entry";
    moduleInfo.moduleName = "entry";
    moduleInfo.moduleType = ModuleType::UNKNOWN;
    moduleInfo.hapPath = "/data/app/el1/bundle/public/com.ohos.demoprocess/entry";
    moduleInfo.compileMode = CompileMode::ES_MODULE;
    moduleInfo.isStageBasedModel = true;
    hapModuleInfos.push_back(moduleInfo);
    bundleInfo.hapModuleInfos = hapModuleInfos;
    std::string mainElementName = "";
    bool res = MainElementUtils::CheckMainUIAbility(bundleInfo, mainElementName);
    EXPECT_FALSE(res);
}

/*
 * Feature: MainElementUtils
 * Function: CheckMainUIAbility
 * SubFunction: NA
 * FunctionPoints:MainElementUtils CheckMainUIAbility
 * EnvConditions: NA
 * CaseDescription: Verify CheckMainUIAbility
 */
HWTEST_F(MainElementUtilsTest, CheckMainUIAbility_002, TestSize.Level1)
{
    AppExecFwk::BundleInfo bundleInfo;
    std::vector<HapModuleInfo> hapModuleInfos;
    HapModuleInfo moduleInfo;
    moduleInfo.name = "entry";
    moduleInfo.moduleName = "entry";
    moduleInfo.moduleType = ModuleType::ENTRY;
    moduleInfo.hapPath = "/data/app/el1/bundle/public/com.ohos.demoprocess/entry";
    moduleInfo.compileMode = CompileMode::ES_MODULE;
    moduleInfo.isStageBasedModel = true;
    moduleInfo.mainElementName = "";
    hapModuleInfos.push_back(moduleInfo);
    bundleInfo.hapModuleInfos = hapModuleInfos;
    std::string mainElementName = "";
    bool res = MainElementUtils::CheckMainUIAbility(bundleInfo, mainElementName);
    EXPECT_FALSE(res);
}

/*
 * Feature: MainElementUtils
 * Function: CheckMainUIAbility
 * SubFunction: NA
 * FunctionPoints:MainElementUtils CheckMainUIAbility
 * EnvConditions: NA
 * CaseDescription: Verify CheckMainUIAbility
 */
HWTEST_F(MainElementUtilsTest, CheckMainUIAbility_003, TestSize.Level1)
{
    AppExecFwk::BundleInfo bundleInfo;
    std::vector<HapModuleInfo> hapModuleInfos;
    HapModuleInfo moduleInfo;
    moduleInfo.name = "entry";
    moduleInfo.moduleName = "entry";
    moduleInfo.moduleType = ModuleType::ENTRY;
    moduleInfo.hapPath = "/data/app/el1/bundle/public/com.ohos.demoprocess/entry";
    moduleInfo.compileMode = CompileMode::ES_MODULE;
    moduleInfo.isStageBasedModel = true;
    moduleInfo.mainElementName = "mainElementName";
    AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.type = AppExecFwk::AbilityType::UNKNOWN;
    moduleInfo.abilityInfos.emplace_back(abilityInfo);
    hapModuleInfos.push_back(moduleInfo);
    bundleInfo.hapModuleInfos = hapModuleInfos;
    std::string mainElementName = "";
    bool res = MainElementUtils::CheckMainUIAbility(bundleInfo, mainElementName);
    EXPECT_FALSE(res);
}

/*
 * Feature: MainElementUtils
 * Function: CheckMainUIAbility
 * SubFunction: NA
 * FunctionPoints:MainElementUtils CheckMainUIAbility
 * EnvConditions: NA
 * CaseDescription: Verify CheckMainUIAbility
 */
HWTEST_F(MainElementUtilsTest, CheckMainUIAbility_004, TestSize.Level1)
{
    AppExecFwk::BundleInfo bundleInfo;
    HapModuleInfo moduleInfo;
    moduleInfo.name = "entry";
    moduleInfo.moduleName = "entry";
    moduleInfo.moduleType = ModuleType::ENTRY;
    moduleInfo.hapPath = "/data/app/el1/bundle/public/com.ohos.demoprocess/entry";
    moduleInfo.compileMode = CompileMode::ES_MODULE;
    moduleInfo.isStageBasedModel = true;
    moduleInfo.mainElementName = "mainElementName";
    AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    abilityInfo.name = "mainElementName";
    moduleInfo.abilityInfos.emplace_back(abilityInfo);
    bundleInfo.hapModuleInfos.push_back(moduleInfo);
    bundleInfo.hapModuleInfos.push_back(moduleInfo);
    bundleInfo.hapModuleInfos.push_back(moduleInfo);
    std::string mainElementName = "mainElementName";
    bool res = MainElementUtils::CheckMainUIAbility(bundleInfo, mainElementName);
    EXPECT_TRUE(res);
}

/*
 * Feature: MainElementUtils
 * Function: CheckStatusBarAbility
 * SubFunction: NA
 * FunctionPoints:MainElementUtils CheckStatusBarAbility
 * EnvConditions: NA
 * CaseDescription: Verify CheckStatusBarAbility
 */
HWTEST_F(MainElementUtilsTest, CheckStatusBarAbility_001, TestSize.Level1)
{
    AppExecFwk::BundleInfo bundleInfo;
    ExtensionAbilityInfo extensionAbilityInfo;
    extensionAbilityInfo.applicationInfo.accessTokenId = 0;
    extensionAbilityInfo.bundleName = "bundleName";
    extensionAbilityInfo.name = "nameTest";
    extensionAbilityInfo.moduleName = "moduleName";
    extensionAbilityInfo.type = AppExecFwk::ExtensionAbilityType::FORM;
    bundleInfo.extensionInfos.emplace_back(extensionAbilityInfo);
    bool res = MainElementUtils::CheckStatusBarAbility(bundleInfo);
    EXPECT_FALSE(res);
}

/*
 * Feature: MainElementUtils
 * Function: CheckStatusBarAbility
 * SubFunction: NA
 * FunctionPoints:MainElementUtils CheckStatusBarAbility
 * EnvConditions: NA
 * CaseDescription: Verify CheckStatusBarAbility
 */
HWTEST_F(MainElementUtilsTest, CheckStatusBarAbility_002, TestSize.Level1)
{
    AppExecFwk::BundleInfo bundleInfo;
    ExtensionAbilityInfo extensionAbilityInfo;
    extensionAbilityInfo.applicationInfo.accessTokenId = 0;
    extensionAbilityInfo.bundleName = "bundleName";
    extensionAbilityInfo.name = "nameTest";
    extensionAbilityInfo.moduleName = "moduleName";
    extensionAbilityInfo.type = AppExecFwk::ExtensionAbilityType::STATUS_BAR_VIEW;
    HapModuleInfo moduleInfo;
    moduleInfo.extensionInfos.emplace_back(extensionAbilityInfo);
    moduleInfo.extensionInfos.emplace_back(extensionAbilityInfo);
    moduleInfo.extensionInfos.emplace_back(extensionAbilityInfo);
    bundleInfo.hapModuleInfos.push_back(moduleInfo);
    bundleInfo.hapModuleInfos.push_back(moduleInfo);
    bundleInfo.hapModuleInfos.push_back(moduleInfo);
    bool res = MainElementUtils::CheckStatusBarAbility(bundleInfo);
    EXPECT_TRUE(res);
}
}  // namespace AAFwk
}  // namespace OHOS
