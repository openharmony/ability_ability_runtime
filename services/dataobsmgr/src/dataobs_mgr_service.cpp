/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "dataobs_mgr_service.h"

#include <functional>
#include <memory>
#include <string>
#include <unistd.h>
#include "string_ex.h"

#include "dataobs_mgr_errors.h"
#include "hilog_wrapper.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AAFwk {
const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<DataObsMgrService>::GetInstance().get());

#define Check()                                                                                 \
do {                                                                                            \
    if (handler_ == nullptr) {                                                                  \
        HILOG_ERROR("handler is nullptr");                                                      \
        return DATAOBS_SERVICE_HANDLER_IS_NULL;                                                 \
    }                                                                                           \
                                                                                                \
    if (dataObsMgrInner_ == nullptr) {                                                          \
        HILOG_ERROR("dataObsMgrInner_ is nullptr");                                             \
        return DATAOBS_SERVICE_INNER_IS_NULL;                                                   \
    }                                                                                           \
} while (0)

DataObsMgrService::DataObsMgrService()
    : SystemAbility(DATAOBS_MGR_SERVICE_SA_ID, true),
      eventLoop_(nullptr),
      handler_(nullptr),
      state_(DataObsServiceRunningState::STATE_NOT_START)
{
    dataObsMgrInner_ = std::make_shared<DataObsMgrInner>();
    dataObsMgrInnerExt_ = std::make_shared<DataObsMgrInnerExt>();
}

DataObsMgrService::~DataObsMgrService()
{}

void DataObsMgrService::OnStart()
{
    if (state_ == DataObsServiceRunningState::STATE_RUNNING) {
        HILOG_INFO("Dataobs Manager Service has already started.");
        return;
    }
    if (!Init()) {
        HILOG_ERROR("failed to init service.");
        return;
    }
    state_ = DataObsServiceRunningState::STATE_RUNNING;
    eventLoop_->Run();
    /* Publish service maybe failed, so we need call this function at the last,
     * so it can't affect the TDD test program */
    if (!Publish(DelayedSingleton<DataObsMgrService>::GetInstance().get())) {
        HILOG_ERROR("Init Publish failed!");
        return;
    }

    HILOG_INFO("Dataobs Manager Service start success.");
}

bool DataObsMgrService::Init()
{
    eventLoop_ = AppExecFwk::EventRunner::Create("DataObsMgrService");
    if (eventLoop_ == nullptr) {
        return false;
    }

    handler_ = std::make_shared<AppExecFwk::EventHandler>(eventLoop_);

    return true;
}

void DataObsMgrService::OnStop()
{
    HILOG_INFO("stop service");
    eventLoop_.reset();
    handler_.reset();
    state_ = DataObsServiceRunningState::STATE_NOT_START;
}

DataObsServiceRunningState DataObsMgrService::QueryServiceState() const
{
    return state_;
}

int DataObsMgrService::RegisterObserver(const Uri &uri, const sptr<IDataAbilityObserver> &dataObserver)
{
    if (dataObserver == nullptr) {
        HILOG_ERROR("dataObserver is nullptr");
        return DATA_OBSERVER_IS_NULL;
    }

    Check();

    auto status = dataObsMgrInner_->HandleRegisterObserver(uri, dataObserver);
    if (status != NO_ERROR) {
        HILOG_ERROR("Observer register failed : %{public}d", status);
        return DATAOBS_SERVICE_POST_TASK_FAILED;
    }
    return NO_ERROR;
}

int DataObsMgrService::UnregisterObserver(const Uri &uri, const sptr<IDataAbilityObserver> &dataObserver)
{
    if (dataObserver == nullptr) {
        HILOG_ERROR("dataObserver is nullptr");
        return DATA_OBSERVER_IS_NULL;
    }

    Check();

    auto status = dataObsMgrInner_->HandleUnregisterObserver(uri, dataObserver);
    if (!status) {
        HILOG_ERROR("Observer unregister failed : %{public}d", status);
        return DATAOBS_SERVICE_POST_TASK_FAILED;
    }
    return NO_ERROR;
}

int DataObsMgrService::NotifyChange(const Uri &uri)
{
    Check();

    {
        std::lock_guard<std::mutex> lck(taskCountMutex_);
        if (taskCount_ >= TASK_COUNT_MAX) {
            HILOG_ERROR("The number of task has reached the upper limit");
            return DATAOBS_SERVICE_TASK_LIMMIT;
        }
        ++taskCount_;
    }

    bool ret = handler_->PostTask([this, &uri]() {
        dataObsMgrInner_->HandleNotifyChange(uri);
        std::lock_guard<std::mutex> lck(taskCountMutex_);
        taskCount_--;
    });
    if (!ret) {
        HILOG_ERROR("Post NotifyChange fail");
        return DATAOBS_SERVICE_POST_TASK_FAILED;
    }

    return NO_ERROR;
}

Status DataObsMgrService::RegisterObserverExt(const Uri &uri, const sptr<IDataAbilityObserver> &dataObserver,
    bool isDescendants)
{
    if (dataObserver == nullptr) {
        HILOG_ERROR("dataObserver is nullptr");
        return DATA_OBSERVER_IS_NULL;
    }

    Check();

    auto innerUri = uri;
    return dataObsMgrInnerExt_->HandleRegisterObserver(innerUri, dataObserver, isDescendants);
}

Status DataObsMgrService::UnregisterObserverExt(const sptr<IDataAbilityObserver> &dataObserver)
{
    if (dataObserver == nullptr) {
        HILOG_ERROR("dataObserver is nullptr");
        return DATA_OBSERVER_IS_NULL;
    }

    Check();

    return dataObsMgrInnerExt_->HandleUnregisterObserver(dataObserver);
}

Status DataObsMgrService::NotifyChangeExt(const std::list<Uri> &uris)
{
    Check();

    {
        std::lock_guard<std::mutex> lck(taskCountExtMutex_);
        if (taskCountExt_ >= TASK_COUNT_MAX) {
            HILOG_ERROR("The number of task has reached the upper limit");
            return DATAOBS_SERVICE_TASK_LIMMIT;
        }
        ++taskCountExt_;
    }

    bool ret = handler_->PostTask([this, &uris]() {
        dataObsMgrInnerExt_->HandleNotifyChange(uris);
        std::lock_guard<std::mutex> lck(taskCountExtMutex_);
        --taskCountExt_;
    });
    if (!ret) {
        HILOG_ERROR("Post NotifyChangeExt fail");
        return DATAOBS_SERVICE_POST_TASK_FAILED;
    }
    return SUCCESS;
}

int DataObsMgrService::Dump(int fd, const std::vector<std::u16string>& args)
{
    std::string result;
    Dump(args, result);
    int ret = dprintf(fd, "%s\n", result.c_str());
    if (ret < 0) {
        HILOG_ERROR("%{public}s, dprintf error.", __func__);
        return DATAOBS_HIDUMP_ERROR;
    }
    return SUCCESS;
}

void DataObsMgrService::Dump(const std::vector<std::u16string>& args, std::string& result) const
{
    auto size = args.size();
    if (size == 0) {
        ShowHelp(result);
        return;
    }

    std::string optionKey = Str16ToStr8(args[0]);
    if (optionKey != "-h") {
        result.append("error: unkown option.\n");
    }
    ShowHelp(result);
}

void DataObsMgrService::ShowHelp(std::string& result) const
{
    result.append("Usage:\n")
        .append("-h                          ")
        .append("help text for the tool\n");
}

std::shared_ptr<EventHandler> DataObsMgrService::GetEventHandler()
{
    return handler_;
}
}  // namespace AAFwk
}  // namespace OHOS
