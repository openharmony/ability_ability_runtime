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

#include "bindable_sub_thread.h"
#include "native_engine/native_engine.h"

using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
class BindableSubThreadTest : public testing::Test {
public:
    void SetUp() override
    {
        NativeReference::ResetCount();
        SetMockHookResult(napi_ok);
    }
};

/**
 * @tc.name: BindSubThreadObject_0100
 * @tc.desc: Bind and get object successfully.
 * @tc.type: FUNC
 */
HWTEST_F(BindableSubThreadTest, BindSubThreadObject_0100, TestSize.Level1)
{
    auto instance = std::make_shared<BindableSubThread>();
    void* env = reinterpret_cast<void*>(0x1);
    auto* ref = new NativeReference();

    instance->BindSubThreadObject(env, ref);
    EXPECT_EQ(instance->GetSubThreadObject(env), ref);
}

/**
 * @tc.name: BindSubThreadObject_0200
 * @tc.desc: Duplicate bind should not replace object.
 * @tc.type: FUNC
 */
HWTEST_F(BindableSubThreadTest, BindSubThreadObject_0200, TestSize.Level1)
{
    auto instance = std::make_shared<BindableSubThread>();
    void* env = reinterpret_cast<void*>(0x2);
    auto* ref1 = new NativeReference();
    auto* ref2 = new NativeReference();

    instance->BindSubThreadObject(env, ref1);
    instance->BindSubThreadObject(env, ref2);
    EXPECT_EQ(instance->GetSubThreadObject(env), ref1);

    delete ref2;
}

/**
 * @tc.name: BindSubThreadObject_0300
 * @tc.desc: Hook failure should not store object.
 * @tc.type: FUNC
 */
HWTEST_F(BindableSubThreadTest, BindSubThreadObject_0300, TestSize.Level1)
{
    auto instance = std::make_shared<BindableSubThread>();
    void* env = reinterpret_cast<void*>(0x3);
    auto* ref = new NativeReference();

    SetMockHookResult(napi_generic_failure);
    instance->BindSubThreadObject(env, ref);
    EXPECT_EQ(instance->GetSubThreadObject(env), nullptr);

    delete ref;
}

/**
 * @tc.name: RemoveSubThreadObject_0100
 * @tc.desc: Remove object path and not found path.
 * @tc.type: FUNC
 */
HWTEST_F(BindableSubThreadTest, RemoveSubThreadObject_0100, TestSize.Level1)
{
    auto instance = std::make_shared<BindableSubThread>();
    void* env = reinterpret_cast<void*>(0x4);
    auto* ref = new NativeReference();

    instance->BindSubThreadObject(env, ref);
    instance->RemoveSubThreadObject(env);
    EXPECT_EQ(instance->GetSubThreadObject(env), nullptr);
    EXPECT_EQ(NativeReference::destructCount, 1);

    instance->RemoveSubThreadObject(env);
}

/**
 * @tc.name: RemoveAllObject_0100
 * @tc.desc: Remove all objects.
 * @tc.type: FUNC
 */
HWTEST_F(BindableSubThreadTest, RemoveAllObject_0100, TestSize.Level1)
{
    auto instance = std::make_shared<BindableSubThread>();
    void* env1 = reinterpret_cast<void*>(0x5);
    void* env2 = reinterpret_cast<void*>(0x6);
    instance->BindSubThreadObject(env1, new NativeReference());
    instance->BindSubThreadObject(env2, new NativeReference());

    instance->RemoveAllObject();
    EXPECT_EQ(instance->GetSubThreadObject(env1), nullptr);
    EXPECT_EQ(instance->GetSubThreadObject(env2), nullptr);
    EXPECT_EQ(NativeReference::destructCount, 2);
}

/**
 * @tc.name: StaticRemoveSubThreadObject_0100
 * @tc.desc: Cover nullptr and expired instance branches.
 * @tc.type: FUNC
 */
HWTEST_F(BindableSubThreadTest, StaticRemoveSubThreadObject_0100, TestSize.Level1)
{
    BindableSubThread::StaticRemoveSubThreadObject(nullptr);

    void* env = reinterpret_cast<void*>(0x7);
    {
        auto instance = std::make_shared<BindableSubThread>();
        instance->BindSubThreadObject(env, new NativeReference());
    }
    TriggerCleanupHook();
    EXPECT_GE(NativeReference::destructCount, 1);
}

/**
 * @tc.name: StaticRemoveSubThreadObject_0200
 * @tc.desc: Cover normal cleanup path.
 * @tc.type: FUNC
 */
HWTEST_F(BindableSubThreadTest, StaticRemoveSubThreadObject_0200, TestSize.Level1)
{
    auto instance = std::make_shared<BindableSubThread>();
    void* env = reinterpret_cast<void*>(0x8);
    instance->BindSubThreadObject(env, new NativeReference());
    EXPECT_NE(instance->GetSubThreadObject(env), nullptr);

    TriggerCleanupHook();
    EXPECT_EQ(instance->GetSubThreadObject(env), nullptr);
    EXPECT_EQ(NativeReference::destructCount, 1);
}
} // namespace AbilityRuntime
} // namespace OHOS
