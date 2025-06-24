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

#include "local_pending_want.h"

#include <gtest/gtest.h>
#include "element_name.h"

using namespace testing::ext;
namespace OHOS::AbilityRuntime::WantAgent {
/*
 * @tc.number    : LocalPendingWant_0100
 * @tc.name      : LocalPendingWant Constructors
 * @tc.desc      : LocalPendingWant Constructors
 */
HWTEST(LocalPendingWantTest, LocalPendingWant_0100, Function | MediumTest | Level1)
{
    std::shared_ptr<AAFwk::Want> want = std::make_shared<AAFwk::Want>();
    LocalPendingWant localPendingWant = LocalPendingWant("TestBundleName", want, 0);
    ASSERT_EQ(localPendingWant.GetBundleName(), "TestBundleName");
}

/*
 * @tc.number    : LocalPendingWant_0200
 * @tc.name      : LocalPendingWant Get & Set bundleName
 * @tc.desc      : LocalPendingWant Get & Set bundleName
 */
HWTEST(LocalPendingWantTest, LocalPendingWant_0200, Function | MediumTest | Level1)
{
    std::shared_ptr<AAFwk::Want> want = std::make_shared<AAFwk::Want>();
    LocalPendingWant localPendingWant = LocalPendingWant("TestBundleName", want, 0);
    localPendingWant.SetBundleName("xxx");
    ASSERT_EQ(localPendingWant.GetBundleName(), "xxx");
}

/*
 * @tc.number    : LocalPendingWant_0300
 * @tc.name      : LocalPendingWant Get & Set uid
 * @tc.desc      : LocalPendingWant Get & Set uid
 */
HWTEST(LocalPendingWantTest, LocalPendingWant_0300, Function | MediumTest | Level1)
{
    std::shared_ptr<AAFwk::Want> want = std::make_shared<AAFwk::Want>();
    LocalPendingWant localPendingWant = LocalPendingWant("TestBundleName", want, 0);
    localPendingWant.SetUid(300);
    ASSERT_EQ(localPendingWant.GetUid(), 300);
}

/*
 * @tc.number    : LocalPendingWant_0400
 * @tc.name      : LocalPendingWant Get & Set operType
 * @tc.desc      : LocalPendingWant Get & Set operType
 */
HWTEST(LocalPendingWantTest, LocalPendingWant_0400, Function | MediumTest | Level1)
{
    std::shared_ptr<AAFwk::Want> want = std::make_shared<AAFwk::Want>();
    LocalPendingWant localPendingWant = LocalPendingWant("TestBundleName", want, 0);
    localPendingWant.SetType(400);
    ASSERT_EQ(localPendingWant.GetType(), 400);
}

/*
 * @tc.number    : LocalPendingWant_0500
 * @tc.name      : LocalPendingWant Get & Set want
 * @tc.desc      : LocalPendingWant Get & Set want
 */
HWTEST(LocalPendingWantTest, LocalPendingWant_0500, Function | MediumTest | Level1)
{
    std::shared_ptr<AAFwk::Want> want = std::make_shared<AAFwk::Want>();
    LocalPendingWant localPendingWant = LocalPendingWant("TestBundleName", want, 0);
    want->SetElement(AppExecFwk::ElementName("TestDeviceId", "TestBundleName", "TestAbilityName"));
    localPendingWant.SetWant(want);
    ASSERT_EQ(localPendingWant.GetWant()->GetElement().GetAbilityName(), "TestAbilityName");
}

/*
 * @tc.number    : LocalPendingWant_0600
 * @tc.name      : LocalPendingWant Get & Set hashCode
 * @tc.desc      : LocalPendingWant Get & Set hashCode
 */
HWTEST(LocalPendingWantTest, LocalPendingWant_0600, Function | MediumTest | Level1)
{
    std::shared_ptr<AAFwk::Want> want = std::make_shared<AAFwk::Want>();
    LocalPendingWant localPendingWant = LocalPendingWant("TestBundleName", want, 0);
    localPendingWant.SetHashCode(600);
    ASSERT_EQ(localPendingWant.GetHashCode(), 600);
}

/*
 * @tc.number    : LocalPendingWant_0700
 * @tc.name      : LocalPendingWant Marshalling & Unmarshalling
 * @tc.desc      : LocalPendingWant Marshalling & Unmarshalling
 */
HWTEST(LocalPendingWantTest, LocalPendingWant_0700, Function | MediumTest | Level1)
{
    std::shared_ptr<AAFwk::Want> want = std::make_shared<AAFwk::Want>();
    LocalPendingWant localPendingWant = LocalPendingWant("TestBundleName", want, 0);
    Parcel parcel;
    localPendingWant.Marshalling(parcel);
    const auto actual = localPendingWant.Unmarshalling(parcel);
    ASSERT_EQ(localPendingWant.GetBundleName(), "TestBundleName");
    ASSERT_EQ(actual->GetBundleName(), "TestBundleName");
}

/*
 * @tc.number    : LocalPendingWant_0800
 * @tc.name      : LocalPendingWant IsEquals
 * @tc.desc      : LocalPendingWant IsEquals
 */
HWTEST(LocalPendingWantTest, LocalPendingWant_0800, Function | MediumTest | Level1)
{
    std::shared_ptr<LocalPendingWant> localPendingWant = nullptr;
    std::shared_ptr<LocalPendingWant> otherLocalPendingWant = nullptr;
    ASSERT_EQ(LocalPendingWant::IsEquals(localPendingWant, otherLocalPendingWant), 0);
    std::shared_ptr<AAFwk::Want> want = std::make_shared<AAFwk::Want>();
    localPendingWant = std::make_shared<LocalPendingWant>("TestBundleName", want, 0);
    otherLocalPendingWant = std::make_shared<LocalPendingWant>("TestBundleName", want, 0);
    ASSERT_EQ(LocalPendingWant::IsEquals(localPendingWant, otherLocalPendingWant), -1);
}
}