/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "zip_file.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
class ZipFileTest : public testing::Test {
public:
  static void SetUpTestCase();
  static void TearDownTestCase();
  void SetUp() override;
  void TearDown() override;
};

void ZipFileTest::SetUpTestCase()
{}

void ZipFileTest::TearDownTestCase()
{}

void ZipFileTest::SetUp()
{}

void ZipFileTest::TearDown()
{}

/**
 * @tc.name: ParseAllEntriesTest_0100
 * @tc.desc: ParseAllEntriesTest Test
 * @tc.type: FUNC
 * @tc.require: issueNoI5NRRS
 */
HWTEST_F(ZipFileTest, ParseAllEntriesTest_0100, TestSize.Level0)
{
  EXPECT_TRUE(ParseAllEntries());
}
}
}
