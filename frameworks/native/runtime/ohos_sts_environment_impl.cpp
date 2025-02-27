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

#include "ohos_sts_environment_impl.h"
#include "hilog_tag_wrapper.h"
#include "ohos_loop_handler.h"
// #include "sys_timer.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
    std::shared_ptr<AppExecFwk::EventHandler> g_eventHandler = nullptr;
}
void OHOSStsEnvironmentImpl::PostTaskToHandler(void* handler, uv_io_cb func, void* work, int status, int priority)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    if (!func || !work) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Invalid parameters");
        return;
    }

    auto task = [func, work, status]() {
        TAG_LOGD(AAFwkTag::STSRUNTIME, "Do uv work");
        func(work, status);
        TAG_LOGD(AAFwkTag::STSRUNTIME, "Do uv work end");
    };

    AppExecFwk::EventQueue::Priority prio = AppExecFwk::EventQueue::Priority::IMMEDIATE;
    switch (priority) {
        case uv_qos_t::uv_qos_user_initiated:
            prio = AppExecFwk::EventQueue::Priority::IMMEDIATE;
            break;
        case uv_qos_t::uv_qos_utility:
            prio = AppExecFwk::EventQueue::Priority::LOW;
            break;
        case uv_qos_t::uv_qos_background:
            prio = AppExecFwk::EventQueue::Priority::IDLE;
            break;
        default:
            prio = AppExecFwk::EventQueue::Priority::HIGH;
            break;
    }

    if (g_eventHandler == nullptr) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Invalid parameters");
        return;
    }
    g_eventHandler->PostTask(task, "uv_io_cb", 0, prio);
}
OHOSStsEnvironmentImpl::OHOSStsEnvironmentImpl()
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
}

OHOSStsEnvironmentImpl::OHOSStsEnvironmentImpl(const std::shared_ptr<AppExecFwk::EventRunner>& eventRunner)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    if (eventRunner != nullptr) {
        TAG_LOGD(AAFwkTag::STSRUNTIME, "Create event handler");
        eventHandler_ = std::make_shared<AppExecFwk::EventHandler>(eventRunner);
        if (eventRunner.get() == AppExecFwk::EventRunner::GetMainEventRunner().get()) {
            g_eventHandler = std::make_shared<AppExecFwk::EventHandler>(eventRunner);
        }
    }
}

OHOSStsEnvironmentImpl::~OHOSStsEnvironmentImpl()
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
}

void OHOSStsEnvironmentImpl::PostTask(const std::function<void()>& task, const std::string& name, int64_t delayTime)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    if (eventHandler_ != nullptr) {
        eventHandler_->PostTask(task, name, delayTime);
    }
}

void OHOSStsEnvironmentImpl::PostSyncTask(const std::function<void()>& task, const std::string& name)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    if (eventHandler_ != nullptr) {
        eventHandler_->PostSyncTask(task, name);
    }
}

void OHOSStsEnvironmentImpl::RemoveTask(const std::string& name)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    if (eventHandler_ != nullptr) {
        eventHandler_->RemoveTask(name);
    }
}

bool OHOSStsEnvironmentImpl::InitLoop(bool isStage)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    loop_ = new (std::nothrow)uv_loop_t;
    if (loop_ == nullptr) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "failed to create uv_loop, async task interface would not work");
        return false;
    }
    if (uv_loop_init(loop_) != ERR_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "failed to init uv_loop, async task interface would not work");
        delete loop_;
        loop_ = nullptr;
        return false;
    }
    auto fd = loop_ != nullptr ? uv_backend_fd(loop_) : -1;
    if (fd < 0) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "get fd failed");
        return false;
    }
    uv_run(loop_, UV_RUN_NOWAIT);

    if (eventHandler_ != nullptr) {
        uint32_t events = AppExecFwk::FILE_DESCRIPTOR_INPUT_EVENT | AppExecFwk::FILE_DESCRIPTOR_OUTPUT_EVENT;
        eventHandler_->AddFileDescriptorListener(fd, events, std::make_shared<OHOSLoopHandler>(loop_), "uvLoopTask");
        TAG_LOGD(AAFwkTag::STSRUNTIME, "uv_register_task_to_event, isStage: %{public}d", isStage);
        if (isStage && (eventHandler_->GetEventRunner()).get() == AppExecFwk::EventRunner::GetMainEventRunner().get()) {
            uv_register_task_to_event(loop_, PostTaskToHandler, nullptr);
        }
    }

    return true;
}

void OHOSStsEnvironmentImpl::DeInitLoop()
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    auto fd = loop_ != nullptr ? uv_backend_fd(loop_) : -1;
    if (fd >= 0 && eventHandler_ != nullptr) {
        eventHandler_->RemoveFileDescriptorListener(fd);
    }
    uv_unregister_task_to_event(loop_);
    RemoveTask(TIMER_TASK);
}

bool OHOSStsEnvironmentImpl::ReInitUVLoop()
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    if (loop_ != nullptr) {
        delete loop_;
        loop_ = nullptr;
    }

    loop_ = new (std::nothrow)uv_loop_t;
    if (loop_ == nullptr) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "failed to create uv_loop, async task interface would not work");
        return false;
    }
    if (uv_loop_init(loop_) != ERR_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "failed to init uv_loop, async task interface would not work");
        delete loop_;
        loop_ = nullptr;
        return false;
    }
    return true;
}
} // namespace AbilityRuntime
} // namespace OHOS
