/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "ffrt_task_utils_wrap.h"
#include "queue_task_handler_wrap.h"
#include "task_handler_wrap.h"
#include "task_utils_wrap.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
constexpr int32_t LONG_TIME_TASK_TIME = 2 * 500000 + 100000; // us
constexpr int32_t SCHEDULE_TIMEOUT = 500; // ms
class TaskHandlerWrapTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;

    std::shared_ptr<TaskHandlerWrap> queueHandler_;
    std::shared_ptr<TaskHandlerWrap> ffrtHandler_;
};

void TaskHandlerWrapTest::SetUpTestCase(void)
{}
void TaskHandlerWrapTest::TearDownTestCase(void)
{}
void TaskHandlerWrapTest::SetUp()
{
    queueHandler_ = TaskHandlerWrap::CreateQueueHandler("TaskHandlerWrapTest");
    ffrtHandler_ = TaskHandlerWrap::GetFfrtHandler();
}
void TaskHandlerWrapTest::TearDown()
{
    queueHandler_.reset();
    ffrtHandler_.reset();
}

/**
 * @tc.name: QueueTest_0010
 * @tc.desc: SubmitTask Test
 * @tc.type: FUNC
 */
HWTEST_F(TaskHandlerWrapTest, QueueTest_0010, TestSize.Level0)
{
    int input = 0;
    auto taskHandle = queueHandler_->SubmitTask([&input]() {
        input = 1;
        });
    EXPECT_TRUE(taskHandle);
    taskHandle.Sync();
    EXPECT_TRUE(input == 1);
}

/**
 * @tc.name: QueueTest_0020
 * @tc.desc: SubmitTask with delay Test
 * @tc.type: FUNC
 */
HWTEST_F(TaskHandlerWrapTest, QueueTest_0020, TestSize.Level0)
{
    int input = 0;
    auto taskHandle = queueHandler_->SubmitTask([&input]() {
        input = 1;
        }, 100);
    EXPECT_TRUE(taskHandle);
    taskHandle.Sync();
    EXPECT_TRUE(input == 1);
}

/**
 * @tc.name: QueueTest_0030
 * @tc.desc: SubmitTask Test
 * @tc.type: FUNC
 */
HWTEST_F(TaskHandlerWrapTest, QueueTest_0030, TestSize.Level0)
{
    auto taskHandle = queueHandler_->SubmitTask([]() {});
    EXPECT_TRUE(taskHandle);
    auto result = taskHandle.Cancel();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: QueueTest_0040
 * @tc.desc: SubmitTask with delay Test
 * @tc.type: FUNC
 */
HWTEST_F(TaskHandlerWrapTest, QueueTest_0040, TestSize.Level0)
{
    auto taskHandle = queueHandler_->SubmitTask([]() {}, 100);
    EXPECT_TRUE(taskHandle);
    auto result = taskHandle.Cancel();
    EXPECT_TRUE(result);
}

/**
 * @tc.name: QueueTest_0050
 * @tc.desc: SubmitTask time task test
 * @tc.type: FUNC
 */
HWTEST_F(TaskHandlerWrapTest, QueueTest_0050, TestSize.Level0)
{
    int input = 0;
    auto taskHandle = queueHandler_->SubmitTask([&input]() {
            usleep(LONG_TIME_TASK_TIME);
            input = 1;
        }, 100);
    EXPECT_TRUE(taskHandle);
    taskHandle.Sync();
    EXPECT_TRUE(input == 1);
}

/**
 * @tc.name: QueueTest_0060
 * @tc.desc: Insert task test
 * @tc.type: FUNC
 */
HWTEST_F(TaskHandlerWrapTest, QueueTest_0060, TestSize.Level0)
{
    queueHandler_->SetPrintTaskLog(true);
    int input = 0;
    auto task1 = [&input]() {
        usleep(LONG_TIME_TASK_TIME);
        input = 1;
    };
    auto handle1 = queueHandler_->SubmitTask(task1, "task1");

    // this task will trigger scheduling timeout
    auto handle2 = queueHandler_->SubmitTask([](){}, TaskAttribute{
        .taskName_ = "task2",
        .timeoutMillis_ = SCHEDULE_TIMEOUT
    });

    int result3 = 0;
    int result4 = 0;
    auto handle3 = queueHandler_->SubmitTask([&input, &result3]() {
            result3 = ++input;
        }, "task3");
    auto handle4 = queueHandler_->SubmitTask([&input, &result4]() {
            result4 = ++input;
        }, TaskAttribute{
            .taskName_ = "task4",
            .insertHead_ = true
        });
    handle1.Sync();
    handle2.Sync();
    handle3.Sync();
    handle4.Sync();
    EXPECT_TRUE(result3 == result4 + 1);
}

/**
 * @tc.name: FfrtTest_0010
 * @tc.desc: SubmitTask Test
 * @tc.type: FUNC
 */
HWTEST_F(TaskHandlerWrapTest, FfrtTest_0010, TestSize.Level0)
{
    int input = 0;
    auto taskHandle = ffrtHandler_->SubmitTask([&input]() {
        input = 1;
        });
    EXPECT_TRUE(taskHandle);
    taskHandle.Sync();
    EXPECT_TRUE(input == 1);
}

/**
 * @tc.name: FfrtTest_0020
 * @tc.desc: SubmitTask with delay Test
 * @tc.type: FUNC
 */
HWTEST_F(TaskHandlerWrapTest, FfrtTest_0020, TestSize.Level0)
{
    int input = 0;
    auto taskHandle = ffrtHandler_->SubmitTask([&input]() {
        input = 1;
        }, 100);
    EXPECT_TRUE(taskHandle);
    taskHandle.Sync();
    EXPECT_TRUE(input == 1);
}

/**
 * @tc.name: FfrtTest_0030
 * @tc.desc: SubmitTask Test
 * @tc.type: FUNC
 */
HWTEST_F(TaskHandlerWrapTest, FfrtTest_0030, TestSize.Level0)
{
    auto taskHandle = ffrtHandler_->SubmitTask([]() {});
    EXPECT_TRUE(taskHandle);
    auto result = taskHandle.Cancel();
    EXPECT_TRUE(result);
}

/**
 * @tc.name: FfrtTest_0040
 * @tc.desc: SubmitTask with delay Test
 * @tc.type: FUNC
 */
HWTEST_F(TaskHandlerWrapTest, FfrtTest_0040, TestSize.Level0)
{
    auto taskHandle = ffrtHandler_->SubmitTask([]() {}, 100);
    EXPECT_TRUE(taskHandle);
    auto result = taskHandle.Cancel();
    EXPECT_TRUE(result);
}

/**
 * @tc.name: RemoveTask_0050
 * @tc.desc: Test removing a task from the task handler after submission.
 * @tc.type: FUNC
 */
HWTEST_F(TaskHandlerWrapTest, RemoveTask_0050, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RemoveTask_0050 start";

    EXPECT_NE(ffrtHandler_, nullptr);

    const std::string name = "test";
    TaskHandle taskHandle;
    EXPECT_FALSE(ffrtHandler_->RemoveTask(name, taskHandle));

    std::function<void()> taskWrap = []() {};
    TaskAttribute taskAttr;
    std::shared_ptr<InnerTaskHandle> innerTaskHandle = ffrtHandler_->SubmitTaskInner(std::move(taskWrap), taskAttr);
    EXPECT_NE(innerTaskHandle, nullptr);
    TaskHandle taskHandleTest(nullptr, innerTaskHandle);
    ffrtHandler_->tasks_.emplace(name, taskHandleTest);
    EXPECT_FALSE(ffrtHandler_->RemoveTask(name, taskHandle));

    EXPECT_EQ(ffrtHandler_->tasks_.size(), 1);
    EXPECT_TRUE(ffrtHandler_->RemoveTask(name, taskHandleTest));
    EXPECT_EQ(ffrtHandler_->tasks_.size(), 0);

    GTEST_LOG_(INFO) << "RemoveTask_0050 end";
}

/**
 * @tc.name: Convert2FfrtQosAndConvert2FfrtPriority_0060
 * @tc.desc: Verify the conversion of task QoS and priority to ffrt equivalents.
 * @tc.type: FUNC
 */
HWTEST_F(TaskHandlerWrapTest, Convert2FfrtQosAndConvert2FfrtPriority_0060, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "Convert2FfrtQosAndConvert2FfrtPriority_0060 start";

    EXPECT_EQ(Convert2FfrtQos(TaskQoS::INHERENT), ffrt::qos_inherit);
    EXPECT_EQ(Convert2FfrtQos(TaskQoS::BACKGROUND), ffrt::qos_background);
    EXPECT_EQ(Convert2FfrtQos(TaskQoS::UTILITY), ffrt::qos_utility);
    EXPECT_EQ(Convert2FfrtQos(TaskQoS::DEFAULT), ffrt::qos_default);
    EXPECT_EQ(Convert2FfrtQos(TaskQoS::USER_INITIATED), ffrt::qos_user_initiated);
    EXPECT_EQ(Convert2FfrtQos(TaskQoS::DEADLINE_REQUEST), ffrt::qos_deadline_request);
    EXPECT_EQ(Convert2FfrtQos(TaskQoS::USER_INTERACTIVE), ffrt::qos_user_interactive);
    EXPECT_EQ(Convert2FfrtPriority(TaskQueuePriority::IMMEDIATE), ffrt_queue_priority_t::ffrt_queue_priority_immediate);
    EXPECT_EQ(Convert2FfrtPriority(TaskQueuePriority::HIGH), ffrt_queue_priority_t::ffrt_queue_priority_high);
    EXPECT_EQ(Convert2FfrtPriority(TaskQueuePriority::LOW), ffrt_queue_priority_t::ffrt_queue_priority_low);
    EXPECT_EQ(Convert2FfrtPriority(TaskQueuePriority::IDLE), ffrt_queue_priority_t::ffrt_queue_priority_idle);

    GTEST_LOG_(INFO) << "Convert2FfrtQosAndConvert2FfrtPriority_0060 end";
}

/**
 * @tc.name: BuildFfrtTaskAttr_0070
 * @tc.desc: Test building task attributes and ensure task execution occurs after delay.
 * @tc.type: FUNC
 */
HWTEST_F(TaskHandlerWrapTest, BuildFfrtTaskAttr_0070, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "BuildFfrtTaskAttr_0070 start";

    EXPECT_NE(ffrtHandler_, nullptr);
    std::shared_ptr<QueueTaskHandlerWrap> queueTaskHandlerWrap =
        std::static_pointer_cast<QueueTaskHandlerWrap>(ffrtHandler_);
    EXPECT_NE(queueTaskHandlerWrap, nullptr);
    int ret = 0;
    std::function<void()> task = [&ret]() { ret++; };
    TaskAttribute taskAttr;
    taskAttr.delayMillis_ = 1;
    taskAttr.taskName_ = "test";
    taskAttr.taskQos_ = TaskQoS::INHERENT;
    taskAttr.taskPriority_ = TaskQueuePriority::IMMEDIATE;
    taskAttr.timeoutMillis_ = 1;
    auto innerTaskHandle = queueTaskHandlerWrap->SubmitTaskInner(std::move(task), taskAttr);
    EXPECT_NE(innerTaskHandle, nullptr);
    EXPECT_NE(ret, 1);

    GTEST_LOG_(INFO) << "BuildFfrtTaskAttr_0070 end";
}
}  // namespace AAFwk
}  // namespace OHOS
