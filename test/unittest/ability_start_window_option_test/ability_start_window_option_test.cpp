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

#include "hilog_tag_wrapper.h"
#include "parcel.h"
#include "start_window_option.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {

class StartWindowOptionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void StartWindowOptionTest::SetUpTestCase(void) {}

void StartWindowOptionTest::TearDownTestCase(void) {}

void StartWindowOptionTest::SetUp() {}

void StartWindowOptionTest::TearDown() {}

/**
 * @tc.number: StartWindowOption_ReadFromParcel_0100
 * @tc.name: ReadFromParcel
 * @tc.desc: ReadFromParcel
 */
HWTEST_F(StartWindowOptionTest, StartWindowOption_ReadFromParcel_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "StartWindowOption_ReadFromParcel_0100 start");

    std::shared_ptr<AAFwk::StartWindowOption> startWindowOption = std::make_shared<AAFwk::StartWindowOption>();
    ASSERT_NE(startWindowOption, nullptr);

    Parcel parcel;
    bool ret = startWindowOption->ReadFromParcel(parcel);
    EXPECT_TRUE(ret);

    TAG_LOGI(AAFwkTag::TEST, "StartWindowOption_ReadFromParcel_0100 end");
}

/**
 * @tc.number: StartWindowOption_Unmarshalling_0100
 * @tc.name: Unmarshalling
 * @tc.desc: Unmarshalling
 */
HWTEST_F(StartWindowOptionTest, StartWindowOption_Unmarshalling_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "StartWindowOption_Unmarshalling_0100 start");

    std::shared_ptr<AAFwk::StartWindowOption> startWindowOption = std::make_shared<AAFwk::StartWindowOption>();
    ASSERT_NE(startWindowOption, nullptr);
    Parcel parcel;
    AAFwk::StartWindowOption* option = startWindowOption->Unmarshalling(parcel);
    EXPECT_NE(option, nullptr);
    delete option;
    option = nullptr;

    TAG_LOGI(AAFwkTag::TEST, "StartWindowOption_Unmarshalling_0100 end");
}

/**
 * @tc.number: StartWindowOption_Marshalling_0100
 * @tc.name: Marshalling
 * @tc.desc: Marshalling
 */
HWTEST_F(StartWindowOptionTest, StartWindowOption_Marshalling_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "StartWindowOption_Marshalling_0100 start");

    std::shared_ptr<AAFwk::StartWindowOption> startWindowOption = std::make_shared<AAFwk::StartWindowOption>();
    ASSERT_NE(startWindowOption, nullptr);
    Parcel parcel;
    bool ret = startWindowOption->Marshalling(parcel);
    EXPECT_TRUE(ret);

    TAG_LOGI(AAFwkTag::TEST, "StartWindowOption_Marshalling_0100 end");
}
} // namespace AbilityRuntime
} // namespace OHOS