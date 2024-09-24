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

#include "window_config.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace testing::ext;
using namespace AAFwk;
using namespace AbilityRuntime;

class WindowConfigTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void WindowConfigTest::SetUpTestCase(void)
{}

void WindowConfigTest::TearDownTestCase(void)
{}

void WindowConfigTest::SetUp(void)
{}

void WindowConfigTest::TearDown(void)
{}

/**
 * @tc.number: Marshalling_001
 * @tc.name: Marshalling
 * @tc.desc: Test whether Marshalling is called normally.
 * @tc.type: FUNC
 */
HWTEST_F(WindowConfigTest, Marshalling_001, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Marshalling_001 start";
    WindowConfig windowConfig;
    Parcel parcel;
    int32_t windowType = 1;
    uint32_t windowId = 2;
    parcel.WriteInt32(windowType);
    parcel.WriteUint32(windowId);

    auto res = windowConfig.Unmarshalling(parcel);
    EXPECT_EQ(res->windowType, windowType);
    EXPECT_EQ(res->windowId, windowId);
    GTEST_LOG_(INFO) << "Marshalling_001 end";
}
} // namespace AbilityRuntime
} // namespace OHOS
