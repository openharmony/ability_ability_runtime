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

 #include <gtest/gtest.h>

 #include "ability_command.h"
 #include "ability_manager_client.h"
 #include "ability_manager_interface.h"
 #include "hilog_tag_wrapper.h"
 #include "mock_ability_manager_stub.h"
 
 using namespace testing::ext;
 using namespace OHOS;
 using namespace OHOS::AAFwk;
 
 namespace {
 const std::string STRING_CLASS_NAME = "ohos.acts.aafwk.ability.test.ConstructorTest#testDataAbilityOtherFunction0010";
 const std::string STRING_USER_TEST_RUNNER = "JSUserTestRunner";
 const std::string STRING_PACKAGE_NAME = "com.example.myapplication";
 const std::string STRING_PACKAGE_NAME1 = "com.example.myapplication1";
 const std::string STRING_BUNDLE_NAME = "com.example.myapplication";
 const std::string STRING_MODULE_NAME = "com.example.myapplication.MyApplication";
 const std::string CLASS = "class";
 const std::string UNITTEST = "unittest";
 const std::string UNITTEST1 = "unittest1";
 const std::string TIME = "20";
const std::string BLACK_ACTION_SELECT_DATA = "ohos.want.action.select";
 }  // namespace
 
 class AbilityCommandThirdTest : public ::testing::Test {
 public:
     static void SetUpTestCase();
     static void TearDownTestCase();
     void SetUp() override;
     void TearDown() override;
 
     void MakeMockObjects() const;
 
     std::string cmd_ = "test";
 };
 
 void AbilityCommandThirdTest::SetUpTestCase()
 {}
 
 void AbilityCommandThirdTest::TearDownTestCase()
 {}
 
 void AbilityCommandThirdTest::SetUp()
 {
     // reset optind to 0
     optind = 0;
 
     // make mock objects
     MakeMockObjects();
 }
 
 void AbilityCommandThirdTest::TearDown()
 {}
 
 void AbilityCommandThirdTest::MakeMockObjects() const
 {
     // mock a stub
     auto managerStubPtr = sptr<IAbilityManager>(new MockAbilityManagerStub());
 
     // set the mock stub
     auto managerClientPtr = AbilityManagerClient::GetInstance();
     managerClientPtr->proxy_ = managerStubPtr;
 }

 /**
 * @tc.number: Ability_Command_Second_Test_0100
 * @tc.name: ExecCommand
 * @tc.desc: Verify the "aa test -W" command.
 */
HWTEST_F(AbilityCommandThirdTest, Ability_Command_Third_Test_0100, Function | MediumTest | Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "Ability_Command_Third_Test_0100 is called");
    char* argv[] = {
        (char*)TOOL_NAME.c_str(),
        (char*)"-U",
        (char*)" ",

    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    AbilityManagerShellCommand cmd(argc, argv);
    Want want;
    std::string windowMode;
    EXPECT_EQ(cmd.MakeWantFromCmd(want, windowMode), OHOS::ERR_INVALID_VALUE);
    want.SetElementName("com.example.test", "MainAbility");
    EXPECT_EQ(cmd.IsImplicitStartAction(want), false);
    want.SetElementName("com.example.test", "");
    want.SetParam(AAFwk::SCREEN_MODE_KEY, ScreenMode::JUMP_SCREEN_MODE);
    EXPECT_EQ(cmd.IsImplicitStartAction(want), false);
    want.SetParam(AAFwk::SCREEN_MODE_KEY, ScreenMode::IDLE_SCREEN_MODE);
    want.SetAction(STRING_PACKAGE_NAME1);
    EXPECT_EQ(cmd.IsImplicitStartAction(want), true);
    want.SetParam(AAFwk::SCREEN_MODE_KEY, ScreenMode::IDLE_SCREEN_MODE);
    want.SetAction(BLACK_ACTION_SELECT_DATA);
    EXPECT_EQ(cmd.IsImplicitStartAction(want), false);
}

 /**
 * @tc.number: Ability_Command_Third_Test_0200
 * @tc.name: ExecCommand
 * @tc.desc: Verify the "aa test -W" command.
 */
HWTEST_F(AbilityCommandThirdTest, Ability_Command_Third_Test_0200, Function | MediumTest | Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "Ability_Command_Third_Test_0200 is called");
    char* argv[] = {
        (char*)TOOL_NAME.c_str(),
        (char*)"-W",
        (char*)" ",

    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    AbilityManagerShellCommand cmd(argc, argv);
    Want want;
    std::string windowMode;
    EXPECT_EQ(cmd.MakeWantFromCmd(want, windowMode), OHOS::ERR_OK);
    want.SetElementName("com.example.test", "");
    want.SetParam(AAFwk::SCREEN_MODE_KEY, ScreenMode::IDLE_SCREEN_MODE);
    want.SetAction(STRING_PACKAGE_NAME1);
    EXPECT_EQ(cmd.StartAbilityWithWait(want), OHOS::ERR_OK);
    want.SetElementName("com.example.test", "MainAbility");
    EXPECT_EQ(cmd.IsImplicitStartAction(want), false);
    EXPECT_EQ(cmd.StartAbilityWithWait(want), OHOS::ERR_OK);
}

 /**
 * @tc.number: Ability_Command_Third_Test_0300
 * @tc.name: ExecCommand
 * @tc.desc: Verify the "aa test -W" command.
 */
HWTEST_F(AbilityCommandThirdTest, Ability_Command_Third_Test_0300, Function | MediumTest | Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "Ability_Command_Third_Test_0300 is called");
    char* argv[] = {
        (char*)TOOL_NAME.c_str(),
        (char*)"-W",
        (char*)" ",

    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    AbilityManagerShellCommand cmd(argc, argv);
    Want want;
    std::string windowMode;
    EXPECT_EQ(cmd.MakeWantFromCmd(want, windowMode), OHOS::ERR_OK);
    AbilityStartWithWaitObserverData data;
    data.reason = 0;
    cmd.FormatOutputForWithWait(want, data);
    data.reason = 1;
    cmd.FormatOutputForWithWait(want, data);
    data.reason = 2;
    cmd.FormatOutputForWithWait(want, data);
    EXPECT_EQ(cmd.startAbilityWithWaitFlag_, true);
}