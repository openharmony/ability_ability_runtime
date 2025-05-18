/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#define private public
#include "ability_context_impl.h"
#define protected public
#include "mock_context.h"
#include "ability_manager_errors.h"
#include "mock_my_flag.h"

namespace OHOS {
namespace AppExecFwk {
using namespace testing::ext;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::AAFwk;

class AbilityContextImplNewTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AbilityContextImplNewTest::SetUpTestCase() {}

void AbilityContextImplNewTest::TearDownTestCase() {}

void AbilityContextImplNewTest::SetUp() {}

void AbilityContextImplNewTest::TearDown() {}

/*
 * Feature: AbilityContextImpl
 * Function: StartAbility
 * SubFunction: NA
 * FunctionPoints: AbilityContextImpl StartAbility
 */
HWTEST_F(AbilityContextImplNewTest, AbilityContextImpl_StartAbility_001, TestSize.Level1)
{
    MyFlag::GetInstance()->SetStartAbility(ERR_CODE_GRANT_URI_PERMISSION);
    auto context = std::make_shared<AbilityContextImpl>();
    Want want;
    int requestCode = 1;
    auto result = context->StartAbility(want, requestCode);
    EXPECT_EQ(result, ERR_CODE_GRANT_URI_PERMISSION);
}

/*
 * Feature: AbilityContextImpl
 * Function: StartAbility
 * SubFunction: NA
 * FunctionPoints: AbilityContextImpl StartAbility
 */
HWTEST_F(AbilityContextImplNewTest, AbilityContextImpl_StartAbility_002, TestSize.Level1)
{
    MyFlag::GetInstance()->SetStartAbility(INNER_ERR);
    auto context = std::make_shared<AbilityContextImpl>();
    Want want;
    StartOptions startOptions;
    int requestCode = 1;
    auto result = context->StartAbility(want, startOptions, requestCode);
    EXPECT_EQ(result, INNER_ERR);
}

/*
 * Feature: AbilityContextImpl
 * Function: StartAbilityAsCaller
 * SubFunction: NA
 * FunctionPoints: AbilityContextImpl StartAbilityAsCaller
 */
HWTEST_F(AbilityContextImplNewTest, AbilityContextImpl_StartAbilityAsCaller_001, TestSize.Level1)
{
    MyFlag::GetInstance()->SetStartAbilityAsCaller(ERR_CODE_NOT_EXIST);
    auto context = std::make_shared<AbilityContextImpl>();
    Want want;
    int requestCode = 1;
    auto result = context->StartAbilityAsCaller(want, requestCode);
    EXPECT_EQ(result, ERR_CODE_NOT_EXIST);
}

/*
 * Feature: AbilityContextImpl
 * Function: StartAbilityAsCaller
 * SubFunction: NA
 * FunctionPoints: AbilityContextImpl StartAbilityAsCaller
 */
HWTEST_F(AbilityContextImplNewTest, AbilityContextImpl_StartAbilityAsCaller_002, TestSize.Level1)
{
    MyFlag::GetInstance()->SetStartAbilityAsCaller(ERR_CODE_GRANT_URI_PERMISSION);
    auto context = std::make_shared<AbilityContextImpl>();
    Want want;
    StartOptions startOptions;
    int requestCode = 1;
    auto result = context->StartAbilityAsCaller(want, startOptions, requestCode);
    EXPECT_EQ(result, ERR_CODE_GRANT_URI_PERMISSION);
}

/*
 * Feature: AbilityContextImpl
 * Function: StartAbilityWithAccount
 * SubFunction: NA
 * FunctionPoints: AbilityContextImpl StartAbilityWithAccount
 */
HWTEST_F(AbilityContextImplNewTest, AbilityContextImpl_StartAbilityWithAccount_001, TestSize.Level1)
{
    MyFlag::GetInstance()->SetStartAbility(INNER_ERR);
    auto context = std::make_shared<AbilityContextImpl>();
    Want want;
    int accountId = 1;
    int requestCode = 1;
    auto result = context->StartAbilityWithAccount(want, accountId, requestCode);
    EXPECT_EQ(result, INNER_ERR);
}

/*
 * Feature: AbilityContextImpl
 * Function: StartAbilityForResult
 * SubFunction: NA
 * FunctionPoints: AbilityContextImpl StartAbilityForResult
 */
HWTEST_F(AbilityContextImplNewTest, AbilityContextImpl_StartAbilityForResult_001, TestSize.Level1)
{
    MyFlag::GetInstance()->SetStartAbility(ERR_CODE_NOT_EXIST);
    auto context = std::make_shared<AbilityContextImpl>();
    Want want;
    int requestCode = 1;
    RuntimeTask task = [](int a, const AAFwk::Want& want, bool flag) {};
    context->resultCallbacks_.insert(make_pair(requestCode, std::move(task)));
    auto result = context->StartAbilityForResult(want, requestCode, std::move(task));
    EXPECT_EQ(context->resultCallbacks_.size(), 0);
    EXPECT_EQ(result, ERR_CODE_NOT_EXIST);
}

/*
 * Feature: AbilityContextImpl
 * Function: StartAbilityForResultWithAccount
 * SubFunction: NA
 * FunctionPoints: AbilityContextImpl StartAbilityForResultWithAccount
 */
HWTEST_F(AbilityContextImplNewTest, AbilityContextImpl_StartAbilityForResultWithAccount_001, TestSize.Level1)
{
    MyFlag::GetInstance()->SetStartAbility(ERR_CODE_GRANT_URI_PERMISSION);
    auto context = std::make_shared<AbilityContextImpl>();
    Want want;
    int requestCode = 1;
    RuntimeTask task = [](int a, const AAFwk::Want& want, bool flag) {};
    context->resultCallbacks_.insert(make_pair(requestCode, std::move(task)));
    auto result = context->StartAbilityForResult(want, requestCode, std::move(task));
    EXPECT_EQ(context->resultCallbacks_.size(), 0);
    EXPECT_EQ(result, ERR_CODE_GRANT_URI_PERMISSION);
}

/*
 * Feature: AbilityContextImpl
 * Function: MoveAbilityToBackground
 * SubFunction: NA
 * FunctionPoints: AbilityContextImpl MoveAbilityToBackground
 */
HWTEST_F(AbilityContextImplNewTest, AbilityContextImpl_MoveAbilityToBackground_001, TestSize.Level1)
{
    MyFlag::GetInstance()->SetMoveAbilityToBackground(INNER_ERR);
    auto context = std::make_shared<AbilityContextImpl>();
    auto result = context->MoveAbilityToBackground();
    EXPECT_EQ(result, INNER_ERR);
}

/*
 * Feature: AbilityContextImpl
 * Function: TerminateSelf
 * SubFunction: NA
 * FunctionPoints: AbilityContextImpl TerminateSelf
 */
HWTEST_F(AbilityContextImplNewTest, AbilityContextImpl_TerminateSelf_001, TestSize.Level1)
{
    MyFlag::GetInstance()->SetTerminateAbility(ERR_CODE_NOT_EXIST);
    auto context = std::make_shared<AbilityContextImpl>();
    auto result = context->TerminateSelf();
    EXPECT_EQ(result, ERR_CODE_NOT_EXIST);
}

/*
 * Feature: AbilityContextImpl
 * Function: CloseAbility
 * SubFunction: NA
 * FunctionPoints: AbilityContextImpl CloseAbility
 */
HWTEST_F(AbilityContextImplNewTest, AbilityContextImpl_CloseAbility_001, TestSize.Level1)
{
    MyFlag::GetInstance()->SetCloseAbility(ERR_CODE_GRANT_URI_PERMISSION);
    auto context = std::make_shared<AbilityContextImpl>();
    auto result = context->CloseAbility();
    EXPECT_EQ(result, ERR_CODE_GRANT_URI_PERMISSION);
}

/*
 * Feature: AbilityContextImpl
 * Function: GetMissionId
 * SubFunction: NA
 * FunctionPoints: AbilityContextImpl GetMissionId
 */
HWTEST_F(AbilityContextImplNewTest, AbilityContextImpl_GetMissionId_001, TestSize.Level1)
{
    auto context = std::make_shared<AbilityContextImpl>();
    int32_t missionId = 1;
    context->missionId_ = 0;
    auto result = context->GetMissionId(missionId);
    EXPECT_EQ(missionId, 0);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: AbilityContextImpl
 * Function: GetMissionId
 * SubFunction: NA
 * FunctionPoints: AbilityContextImpl GetMissionId
 */
HWTEST_F(AbilityContextImplNewTest, AbilityContextImpl_GetMissionId_002, TestSize.Level1)
{
    auto context = std::make_shared<AbilityContextImpl>();
    int32_t missionId = 1;
    context->missionId_ = -1;
    MyFlag::GetInstance()->SetMissionId(8);
    MyFlag::GetInstance()->SetMissionIdByToken(ERR_OK);
    auto result = context->GetMissionId(missionId);
    EXPECT_EQ(missionId, 8);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: AbilityContextImpl
 * Function: SetMissionLabel
 * SubFunction: NA
 * FunctionPoints: AbilityContextImpl SetMissionLabel
 */
HWTEST_F(AbilityContextImplNewTest, AbilityContextImpl_SetMissionLabel_001, TestSize.Level1)
{
    auto context = std::make_shared<AbilityContextImpl>();
    std::string label = "label";
    context->isHook_ = false;
    MyFlag::GetInstance()->SetMissionLabel(ERR_OK);
    auto result = context->SetMissionLabel(label);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: AbilityContextImpl
 * Function: SetMissionIcon
 * SubFunction: NA
 * FunctionPoints: AbilityContextImpl SetMissionIcon
 */
HWTEST_F(AbilityContextImplNewTest, AbilityContextImpl_SetMissionIcon_001, TestSize.Level1)
{
    auto context = std::make_shared<AbilityContextImpl>();
    MyFlag::GetInstance()->SetMissionIcon(ERR_OK);
    auto result = context->SetMissionIcon(nullptr);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: AbilityContextImpl
 * Function: IsUIExtensionExist
 * SubFunction: NA
 * FunctionPoints: AbilityContextImpl IsUIExtensionExist
 */
HWTEST_F(AbilityContextImplNewTest, AbilityContextImpl_IsUIExtensionExist_001, TestSize.Level1)
{
    auto context = std::make_shared<AbilityContextImpl>();
    context->uiExtensionMap_.clear();
    Want want;
    auto result = context->IsUIExtensionExist(want);
    EXPECT_FALSE(result);
}

/*
 * Feature: AbilityContextImpl
 * Function: RequestModalUIExtension
 * SubFunction: NA
 * FunctionPoints: AbilityContextImpl RequestModalUIExtension
 */
HWTEST_F(AbilityContextImplNewTest, AbilityContextImpl_RequestModalUIExtension_001, TestSize.Level1)
{
    auto context = std::make_shared<AbilityContextImpl>();
    MyFlag::GetInstance()->SetRequestModalUIExtension(ERR_CODE_NOT_EXIST);
    Want want;
    auto result = context->RequestModalUIExtension(want);
    EXPECT_EQ(result, ERR_CODE_NOT_EXIST);
}

/*
 * Feature: AbilityContextImpl
 * Function: ChangeAbilityVisibility
 * SubFunction: NA
 * FunctionPoints: AbilityContextImpl ChangeAbilityVisibility
 */
HWTEST_F(AbilityContextImplNewTest, AbilityContextImpl_ChangeAbilityVisibility_001, TestSize.Level1)
{
    auto context = std::make_shared<AbilityContextImpl>();
    MyFlag::GetInstance()->SetChangeAbilityVisibility(INNER_ERR);
    auto result = context->ChangeAbilityVisibility(false);
    EXPECT_EQ(result, INNER_ERR);
}

/*
 * Feature: AbilityContextImpl
 * Function: AddFreeInstallObserver
 * SubFunction: NA
 * FunctionPoints: AbilityContextImpl AddFreeInstallObserver
 */
HWTEST_F(AbilityContextImplNewTest, AbilityContextImpl_AddFreeInstallObserver_001, TestSize.Level1)
{
    auto context = std::make_shared<AbilityContextImpl>();
    MyFlag::GetInstance()->SetAddFreeInstallObserver(INNER_ERR);
    auto result = context->AddFreeInstallObserver(nullptr);
    EXPECT_EQ(result, INNER_ERR);
}

/*
 * Feature: AbilityContextImpl
 * Function: OpenAtomicService
 * SubFunction: NA
 * FunctionPoints: AbilityContextImpl OpenAtomicService
 */
HWTEST_F(AbilityContextImplNewTest, AbilityContextImpl_OpenAtomicService_001, TestSize.Level1)
{
    auto context = std::make_shared<AbilityContextImpl>();
    MyFlag::GetInstance()->SetOpenAtomicService(ERR_CODE_NOT_EXIST);
    Want want;
    StartOptions options;
    int requestCode = 1;
    RuntimeTask task = [](int a, const Want& want, bool flag) {};
    context->resultCallbacks_.insert(make_pair(requestCode, std::move(task)));
    auto result = context->OpenAtomicService(want, options, requestCode, std::move(task));
    EXPECT_TRUE(context->resultCallbacks_.size() == 0);
    EXPECT_EQ(result, ERR_CODE_NOT_EXIST);
}

/*
 * Feature: AbilityContextImpl
 * Function: SetRestoreEnabled
 * SubFunction: NA
 * FunctionPoints: AbilityContextImpl SetRestoreEnabled
 */
HWTEST_F(AbilityContextImplNewTest, AbilityContextImpl_SetRestoreEnabled_001, TestSize.Level1)
{
    auto context = std::make_shared<AbilityContextImpl>();
    context->isHook_ = true;
    context->restoreEnabled_.store(false);
    bool enabled = true;
    context->SetRestoreEnabled(enabled);
    EXPECT_EQ(context->restoreEnabled_.load(), false);
}

/*
 * Feature: AbilityContextImpl
 * Function: SetRestoreEnabled
 * SubFunction: NA
 * FunctionPoints: AbilityContextImpl SetRestoreEnabled
 */
HWTEST_F(AbilityContextImplNewTest, AbilityContextImpl_SetRestoreEnabled_002, TestSize.Level1)
{
    auto context = std::make_shared<AbilityContextImpl>();
    context->isHook_ = false;
    context->restoreEnabled_.store(false);
    bool enabled = true;
    context->SetRestoreEnabled(enabled);
    EXPECT_EQ(context->restoreEnabled_.load(), true);
}

/*
 * Feature: AbilityContextImpl
 * Function: RevokeDelegator
 * SubFunction: NA
 * FunctionPoints: AbilityContextImpl RevokeDelegator
 */
HWTEST_F(AbilityContextImplNewTest, AbilityContextImpl_RevokeDelegator_001, TestSize.Level1)
{
    auto context = std::make_shared<AbilityContextImpl>();
    auto result = context->RevokeDelegator();
    EXPECT_EQ(result, ERR_CAPABILITY_NOT_SUPPORT);
}
} // namespace AppExecFwk
} // namespace OHOS