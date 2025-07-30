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

#include "ability_manager_xcollie.h"
#include "xcollie/xcollie.h"

using namespace testing;
using namespace testing::ext;

namespace HiviewDFX {
std::shared_ptr<XCollie> XCollie::instance;
XCollie &XCollie::GetInstance()
{
    if (instance == nullptr) {
        instance = std::make_shared<XCollie>();
    }
    return *instance;
}
} // namespace HiviewDFX

namespace OHOS {
namespace AbilityRuntime {
using namespace HiviewDFX;
class AbilityManagerXcollieTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void AbilityManagerXcollieTest::SetUpTestCase(void)
{}
void AbilityManagerXcollieTest::TearDownTestCase(void)
{}
void AbilityManagerXcollieTest::SetUp()
{
    XCollie::instance = std::make_shared<XCollie>();
}
void AbilityManagerXcollieTest::TearDown()
{
    XCollie::instance.reset();
}

/**
 * @tc.name: AbilityManagerXCollie_0010
 * @tc.desc: set timer normally.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerXcollieTest, AbilityManagerXCollie_0010, TestSize.Level1)
{
    std::string tag = "tag";
    uint32_t timeoutSeconds = 0;
    bool ignore = false;
    EXPECT_CALL(*XCollie::instance, SetTimer).Times(1)
        .WillOnce(Return(1));
    AbilityManagerXCollie testObj(tag, timeoutSeconds, ignore);
    EXPECT_EQ(testObj.id_, 1);
    EXPECT_FALSE(testObj.isCanceled_);
    EXPECT_CALL(*XCollie::instance, CancelTimer).Times(1);
}

/**
 * @tc.name: AbilityManagerXCollie_0020
 * @tc.desc: ignore and no set timer.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerXcollieTest, AbilityManagerXCollie_0020, TestSize.Level1)
{
    std::string tag = "tag";
    uint32_t timeoutSeconds = 0;
    bool ignore = true;
    EXPECT_CALL(*XCollie::instance, SetTimer).Times(0);
    AbilityManagerXCollie testObj(tag, timeoutSeconds, ignore);
    EXPECT_EQ(testObj.id_, -1);
    EXPECT_TRUE(testObj.isCanceled_);
    EXPECT_CALL(*XCollie::instance, CancelTimer).Times(0);
}

/**
 * @tc.name: CancelAbilityManagerXCollie_0010
 * @tc.desc: cancel normal timer.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerXcollieTest, CancelAbilityManagerXCollie_0010, TestSize.Level1)
{
    std::string tag = "tag";
    uint32_t timeoutSeconds = 0;
    bool ignore = false;
    EXPECT_CALL(*XCollie::instance, SetTimer).Times(1)
        .WillOnce(Return(1));
    AbilityManagerXCollie testObj(tag, timeoutSeconds, ignore);
    EXPECT_CALL(*XCollie::instance, CancelTimer).Times(1);
    testObj.CancelAbilityManagerXCollie();
    EXPECT_TRUE(testObj.isCanceled_);

    EXPECT_CALL(*XCollie::instance, CancelTimer).Times(0);
    testObj.CancelAbilityManagerXCollie();
}
} // namespace AbilityRuntime
} // namespace OHOS
