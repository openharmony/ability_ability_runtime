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

#include "ability_manager_errors.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "mock_vertical_panel_manager.h"
#include "start_vertical_panel.h"

using namespace testing::ext;
using namespace testing;
using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace AppExecFwk {

constexpr const char *SCREENMODE = "screenMode";
constexpr const char *BUNDLENAME = "bundleName";
constexpr const char *MODULENAME = "moduleName";
constexpr const char *ABILITYNAME = "abilityName";
constexpr const char *WINDOWID = "windowId";

class StartVerticalPanelTest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {}

    static void TearDownTestCase(void)
    {}

    void SetUp() override
    {
        mockContext = std::make_shared<MockAbilityContext>();
        mockPanelStartCallback = std::make_shared<MockPanelStartCallback>();
        mockScreenConfig.type = "test";
        mockScreenConfig.sourceAppInfo = mockSourceAppInfo;
        ON_CALL(*mockContext, GetUIContent()).WillByDefault(Return(&mockUIContent));
        ON_CALL(mockUIContent, CreateModalUIExtension(_, _, _)).WillByDefault(Return(1));
    }

    void TearDown()
    {}
    std::shared_ptr<MockAbilityContext> mockContext;
    std::shared_ptr<MockPanelStartCallback> mockPanelStartCallback;
    Ace::MockUIContent mockUIContent;
    AAFwk::WantParams mockWantParams;
    AAFwk::ScreenConfig mockScreenConfig;
    std::map<std::string, std::string> mockSourceAppInfo = {
        {SCREENMODE, "0"}, {BUNDLENAME, "0"}, {MODULENAME, "0"}, {ABILITYNAME, "0"}, {WINDOWID, "0"}};
};

/*
 * Feature: VerticalPanelManager
 * Function: StartVerticalPanel
 * SubFunction: NA
 * FunctionPoints: StartVerticalPanel Parameter Validation
 */
HWTEST_F(StartVerticalPanelTest, StartVerticalPanel_001, TestSize.Level1)
{
    std::shared_ptr<AbilityContext> context = nullptr;
    // context nullptr
    ErrCode result = StartVerticalPanel(context, mockWantParams, mockScreenConfig, mockPanelStartCallback);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
}

/*
 * Feature: VerticalPanelManager
 * Function: StartVerticalPanel
 * SubFunction: NA
 * FunctionPoints: StartVerticalPanel UIContent Validation
 */
HWTEST_F(StartVerticalPanelTest, StartVerticalPanel_002, TestSize.Level1)
{
    EXPECT_CALL(*mockContext, GetUIContent()).WillOnce(Return(nullptr));
    // ui context nullptr
    ErrCode result = StartVerticalPanel(mockContext, mockWantParams, mockScreenConfig, mockPanelStartCallback);
    EXPECT_EQ(result, AAFwk::ERR_MAIN_WINDOW_NOT_EXIST);
}

/*
 * Feature: VerticalPanelManager
 * Function: StartVerticalPanel
 * SubFunction: NA
 * FunctionPoints: StartVerticalPanel Callback Validation
 */
HWTEST_F(StartVerticalPanelTest, StartVerticalPanel_003, TestSize.Level1)
{
    // panelStartCallback nullptr
    ErrCode result = StartVerticalPanel(mockContext, mockWantParams, mockScreenConfig, nullptr);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
}

/*
 * Feature: VerticalPanelManager
 * Function: StartVerticalPanel
 * SubFunction: NA
 * FunctionPoints: StartVerticalPanel Normal Execution
 */
HWTEST_F(StartVerticalPanelTest, StartVerticalPanel_004, TestSize.Level1)
{
    ErrCode result = StartVerticalPanel(mockContext, mockWantParams, mockScreenConfig, mockPanelStartCallback);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: VerticalPanelManager
 * Function: StartVerticalPanel
 * SubFunction: NA
 * FunctionPoints: StartVerticalPanel UI Extension Creation Failure
 */
HWTEST_F(StartVerticalPanelTest, StartVerticalPanel_005, TestSize.Level1)
{
    EXPECT_CALL(mockUIContent, CreateModalUIExtension(_, _, _)).WillOnce(Return(0));
    ErrCode result = StartVerticalPanel(mockContext, mockWantParams, mockScreenConfig, mockPanelStartCallback);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
}

/*
 * Feature: VerticalPanelManager
 * Function: StartVerticalPanel
 * SubFunction: NA
 * FunctionPoints: StartVerticalPanel Source App Info Validation
 */
HWTEST_F(StartVerticalPanelTest, StartVerticalPanel_006, TestSize.Level1)
{
    // 缺少 SCREENMODE
    std::map<std::string, std::string> incompleteAppInfo = mockSourceAppInfo;
    incompleteAppInfo.erase(SCREENMODE);
    mockScreenConfig.sourceAppInfo = incompleteAppInfo;

    ErrCode result = StartVerticalPanel(mockContext, mockWantParams, mockScreenConfig, mockPanelStartCallback);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
}

/*
 * Feature: VerticalPanelManager
 * Function: StartVerticalPanel
 * SubFunction: NA
 * FunctionPoints: StartVerticalPanel Source App Info Validation
 */
HWTEST_F(StartVerticalPanelTest, StartVerticalPanel_007, TestSize.Level1)
{
    // 缺少 BUNDLENAME
    std::map<std::string, std::string> incompleteAppInfo = mockSourceAppInfo;
    incompleteAppInfo.erase(BUNDLENAME);
    mockScreenConfig.sourceAppInfo = incompleteAppInfo;

    ErrCode result = StartVerticalPanel(mockContext, mockWantParams, mockScreenConfig, mockPanelStartCallback);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
}

/*
 * Feature: VerticalPanelManager
 * Function: StartVerticalPanel
 * SubFunction: NA
 * FunctionPoints: StartVerticalPanel Source App Info Validation
 */
HWTEST_F(StartVerticalPanelTest, StartVerticalPanel_008, TestSize.Level1)
{
    // 缺少 MODULENAME
    std::map<std::string, std::string> incompleteAppInfo = mockSourceAppInfo;
    incompleteAppInfo.erase(MODULENAME);
    mockScreenConfig.sourceAppInfo = incompleteAppInfo;

    ErrCode result = StartVerticalPanel(mockContext, mockWantParams, mockScreenConfig, mockPanelStartCallback);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
}

/*
 * Feature: VerticalPanelManager
 * Function: StartVerticalPanel
 * SubFunction: NA
 * FunctionPoints: StartVerticalPanel Source App Info Validation
 */
HWTEST_F(StartVerticalPanelTest, StartVerticalPanel_009, TestSize.Level1)
{
    // 缺少 ABILITYNAME
    std::map<std::string, std::string> incompleteAppInfo = mockSourceAppInfo;
    incompleteAppInfo.erase(ABILITYNAME);
    mockScreenConfig.sourceAppInfo = incompleteAppInfo;

    ErrCode result = StartVerticalPanel(mockContext, mockWantParams, mockScreenConfig, mockPanelStartCallback);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
}

/*
 * Feature: VerticalPanelManager
 * Function: StartVerticalPanel
 * SubFunction: NA
 * FunctionPoints: StartVerticalPanel Source App Info Validation
 */
HWTEST_F(StartVerticalPanelTest, StartVerticalPanel_010, TestSize.Level1)
{
    // 缺少 WINDOWID
    std::map<std::string, std::string> incompleteAppInfo = mockSourceAppInfo;
    incompleteAppInfo.erase(WINDOWID);
    mockScreenConfig.sourceAppInfo = incompleteAppInfo;

    ErrCode result = StartVerticalPanel(mockContext, mockWantParams, mockScreenConfig, mockPanelStartCallback);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
}

}  // namespace AppExecFwk
}  // namespace OHOS