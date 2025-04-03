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

#include "gtest/gtest.h"
#include <string>
#include <vector>
#include "parcel.h"
#include <memory>
#include "dialog_session_info.h"
#include "hilog_tag_wrapper.h"

using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
class DialogAbilityInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DialogAbilityInfoTest::SetUpTestCase()
{}

void DialogAbilityInfoTest::TearDownTestCase()
{}

void DialogAbilityInfoTest::SetUp()
{}

void DialogAbilityInfoTest::TearDown()
{}

/**
 * @tc.name: GetURI_001
 * @tc.desc: GetURI Test
 * @tc.type: FUNC
 */
HWTEST_F(DialogAbilityInfoTest, GetURI_001, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "GetURI_001 is start");
    DialogAbilityInfo dialogAbilityInfo;
    dialogAbilityInfo.bundleName = "com.example.app";
    dialogAbilityInfo.moduleName = "main";
    dialogAbilityInfo.abilityName = "home";
    dialogAbilityInfo.bundleIconId = 1;
    dialogAbilityInfo.bundleLabelId = 2;
    dialogAbilityInfo.abilityIconId = 3;
    dialogAbilityInfo.abilityLabelId = 4;
    dialogAbilityInfo.visible = true;
    dialogAbilityInfo.appIndex = 5;
    dialogAbilityInfo.multiAppMode.multiAppModeType = AppExecFwk::MultiAppModeType::MULTI_INSTANCE;
    dialogAbilityInfo.multiAppMode.maxCount = 10;

    std::string expectedURI = "com.example.app/main/home/1/2/3/4/1/5/1/10";
    EXPECT_EQ(dialogAbilityInfo.GetURI(), expectedURI);
}

/**
 * @tc.name: GetURI_002
 * @tc.desc: GetURI Test
 * @tc.type: FUNC
 */
HWTEST_F(DialogAbilityInfoTest, GetURI_002, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "GetURI_002 is start");
    DialogAbilityInfo dialogAbilityInfo;
    std::string expectedURI = "///0/0/0/0/1/0/0/0";
    EXPECT_EQ(dialogAbilityInfo.GetURI(), expectedURI);
}

/**
 * @tc.name: ParseURI_002
 * @tc.desc: ParseURI Test
 * @tc.type: FUNC
 */
HWTEST_F(DialogAbilityInfoTest, ParseURI_002, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "ParseURI_002 is start");
    DialogAbilityInfo dialogAbilityInfo;
    std::string uri = "bundleName/moduleName/abilityName/0/1/2/3/0/4/5/6/7";
    EXPECT_FALSE(dialogAbilityInfo.ParseURI(uri));
}

/**
 * @tc.name: ParseURI_003
 * @tc.desc: ParseURI Test
 * @tc.type: FUNC
 */
HWTEST_F(DialogAbilityInfoTest, ParseURI_003, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "ParseURI_003 is start");
    DialogAbilityInfo dialogAbilityInfo;
    std::string uri = dialogAbilityInfo.GetURI();
    EXPECT_TRUE(dialogAbilityInfo.ParseURI(uri));
}

/**
 * @tc.name: Split_001
 * @tc.desc: Split Test
 * @tc.type: FUNC
 */
HWTEST_F(DialogAbilityInfoTest, Split_001, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "Split_001 is start");
    DialogAbilityInfo dialogAbilityInfo;
    std::vector<std::string> vec;
    dialogAbilityInfo.Split("", ",", vec);
    EXPECT_EQ(vec.size(), 0);
}

/**
 * @tc.name: Split_002
 * @tc.desc: Split Test
 * @tc.type: FUNC
 */
HWTEST_F(DialogAbilityInfoTest, Split_002, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "Split_002 is start");
    DialogAbilityInfo dialogAbilityInfo;
    std::vector<std::string> vec;
    dialogAbilityInfo.Split("Hello", ",", vec);
    EXPECT_EQ(vec.size(), 1);
    EXPECT_EQ(vec[0], "Hello");
}

/**
 * @tc.name: Split_003
 * @tc.desc: Split Test
 * @tc.type: FUNC
 */
HWTEST_F(DialogAbilityInfoTest, Split_003, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "Split_003 is start");
    DialogAbilityInfo dialogAbilityInfo;
    std::vector<std::string> vec;
    dialogAbilityInfo.Split("Hello,World,Test", ",", vec);
    EXPECT_EQ(vec.size(), 3);
    EXPECT_EQ(vec[0], "Hello");
    EXPECT_EQ(vec[1], "World");
    EXPECT_EQ(vec[2], "Test");
}

/**
 * @tc.name: Split_004
 * @tc.desc: Split Test
 * @tc.type: FUNC
 */
HWTEST_F(DialogAbilityInfoTest, Split_004, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "Split_004 is start");
    DialogAbilityInfo dialogAbilityInfo;
    std::vector<std::string> vec;
    dialogAbilityInfo.Split("Hello,World,", ",", vec);
    EXPECT_EQ(vec.size(), 2);
    EXPECT_EQ(vec[0], "Hello");
    EXPECT_EQ(vec[1], "World");
}

/**
 * @tc.name: ReadFromParcel_001
 * @tc.desc: ReadFromParcel Test
 * @tc.type: FUNC
 */
HWTEST_F(DialogAbilityInfoTest, ReadFromParcel_001, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "ReadFromParcel_001 is start");
    DialogSessionInfo dialogSessionInfo;
    Parcel parcel;
    std::string invalidUri = "invalidUri";
    parcel.WriteString16(Str8ToStr16(invalidUri));
    EXPECT_FALSE(dialogSessionInfo.ReadFromParcel(parcel));
    TAG_LOGI(AAFwkTag::TEST, "ReadFromParcel_001 is end");
}

/**
 * @tc.name: ReadFromParcel_002
 * @tc.desc: ReadFromParcel Test
 * @tc.type: FUNC
 */
HWTEST_F(DialogAbilityInfoTest, ReadFromParcel_002, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "ReadFromParcel_002 is start");
    DialogSessionInfo dialogSessionInfo;
    Parcel parcel;
    DialogAbilityInfo dialogAbilityInfo;
    std::string validUri = dialogAbilityInfo.GetURI();
    parcel.WriteString16(Str8ToStr16(validUri));
    EXPECT_FALSE(dialogSessionInfo.ReadFromParcel(parcel));
    TAG_LOGI(AAFwkTag::TEST, "ReadFromParcel_002 is end");
}

/**
 * @tc.name: ReadFromParcel_003
 * @tc.desc: ReadFromParcel Test
 * @tc.type: FUNC
 */
HWTEST_F(DialogAbilityInfoTest, ReadFromParcel_003, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "ReadFromParcel_003 is start");
    DialogSessionInfo dialogSessionInfo;
    Parcel parcel;
    DialogAbilityInfo dialogAbilityInfo;
    std::string validUri = dialogAbilityInfo.GetURI();
    parcel.WriteString16(Str8ToStr16(validUri));
    int32_t validSize = 1;
    parcel.WriteInt32(validSize);
    EXPECT_FALSE(dialogSessionInfo.ReadFromParcel(parcel));
    TAG_LOGI(AAFwkTag::TEST, "ReadFromParcel_003 is end");
}

/**
 * @tc.name: ReadFromParcel_004
 * @tc.desc: ReadFromParcel Test
 * @tc.type: FUNC
 */
HWTEST_F(DialogAbilityInfoTest, ReadFromParcel_004, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "ReadFromParcel_004 is start");
    DialogSessionInfo dialogSessionInfo;
    Parcel parcel;
    DialogAbilityInfo dialogAbilityInfo;
    std::string validUri = dialogAbilityInfo.GetURI();
    parcel.WriteString16(Str8ToStr16(validUri));
    int32_t validSize = 1;
    parcel.WriteInt32(validSize);
    dialogSessionInfo.targetAbilityInfos.emplace_back(dialogAbilityInfo);
    std::string invalidUri = "invalidUri";
    parcel.WriteString16(Str8ToStr16(invalidUri));
    EXPECT_FALSE(dialogSessionInfo.ReadFromParcel(parcel));
    TAG_LOGI(AAFwkTag::TEST, "ReadFromParcel_004 is end");
}

/**
 * @tc.name: ReadFromParcel_005
 * @tc.desc: ReadFromParcel Test
 * @tc.type: FUNC
 */
HWTEST_F(DialogAbilityInfoTest, ReadFromParcel_005, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "ReadFromParcel_005 is start");
    DialogSessionInfo dialogSessionInfo;
    Parcel parcel;
    DialogAbilityInfo dialogAbilityInfo;
    std::string validUri = dialogAbilityInfo.GetURI();
    parcel.WriteString16(Str8ToStr16(validUri));
    int32_t validSize = 1;
    parcel.WriteInt32(validSize);
    dialogSessionInfo.targetAbilityInfos.emplace_back(dialogAbilityInfo);
    std::string invalidUri = dialogAbilityInfo.GetURI();
    parcel.WriteString16(Str8ToStr16(invalidUri));
    EXPECT_FALSE(dialogSessionInfo.ReadFromParcel(parcel));
    TAG_LOGI(AAFwkTag::TEST, "ReadFromParcel_005 is end");
}

/**
 * @tc.name: ReadFromParcel_006
 * @tc.desc: ReadFromParcel Test
 * @tc.type: FUNC
 */
HWTEST_F(DialogAbilityInfoTest, ReadFromParcel_006, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "ReadFromParcel_006 is start");
    DialogSessionInfo dialogSessionInfo;
    Parcel parcel;
    DialogAbilityInfo dialogAbilityInfo;
    std::string validUri = dialogAbilityInfo.GetURI();
    parcel.WriteString16(Str8ToStr16(validUri));
    int32_t validSize = 1;
    parcel.WriteInt32(validSize);
    dialogSessionInfo.targetAbilityInfos.emplace_back(dialogAbilityInfo);
    std::string invalidUri = dialogAbilityInfo.GetURI();
    parcel.WriteString16(Str8ToStr16(invalidUri));
    AAFwk::WantParams params;
    Parcelable *parcelable = &params;
    parcel.WriteParcelable(parcelable);
    EXPECT_TRUE(dialogSessionInfo.ReadFromParcel(parcel));
    TAG_LOGI(AAFwkTag::TEST, "ReadFromParcel_006 is end");
}

/**
 * @tc.name: Marshalling_002
 * @tc.desc: Marshalling Test
 * @tc.type: FUNC
 */
HWTEST_F(DialogAbilityInfoTest, Marshalling_002, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "Marshalling_002 is start");
    Parcel parcel;
    DialogSessionInfo dialogSessionInfo;
    dialogSessionInfo.targetAbilityInfos.clear();
    EXPECT_TRUE(dialogSessionInfo.Marshalling(parcel));
}

/**
 * @tc.name: Unmarshalling_001
 * @tc.desc: Unmarshalling Test
 * @tc.type: FUNC
 */
HWTEST_F(DialogAbilityInfoTest, Unmarshalling_001, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "Unmarshalling_001 is start");
    Parcel parcel;
    DialogSessionInfo dialogSessionInfo;
    DialogSessionInfo *info = DialogSessionInfo::Unmarshalling(parcel);
    EXPECT_EQ(info, nullptr);
}

/**
 * @tc.name: Unmarshalling_002
 * @tc.desc: Unmarshalling Test
 * @tc.type: FUNC
 */
HWTEST_F(DialogAbilityInfoTest, Unmarshalling_002, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "Unmarshalling_002 is start");
    Parcel parcel;
    DialogAbilityInfo dialogAbilityInfo;
    DialogSessionInfo dialogSessionInfo;
    std::string validUri = dialogAbilityInfo.GetURI();
    parcel.WriteString16(Str8ToStr16(validUri));
    int32_t validSize = 1;
    parcel.WriteInt32(validSize);
    dialogSessionInfo.targetAbilityInfos.emplace_back(dialogAbilityInfo);
    std::string invalidUri = dialogAbilityInfo.GetURI();
    parcel.WriteString16(Str8ToStr16(invalidUri));
    AAFwk::WantParams params;
    Parcelable *parcelable = &params;
    parcel.WriteParcelable(parcelable);
    DialogSessionInfo *info = DialogSessionInfo::Unmarshalling(parcel);
    EXPECT_NE(info, nullptr);
    delete info;
}
} // AAFwk
} // OHOS