/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "app_domain_verify_mgr_client.h"

namespace OHOS {
namespace AppDomainVerify {
bool AppDomainVerifyMgrClient::isAtomicServiceUrlFlag_ = false;
AAFwk::Want AppDomainVerifyMgrClient::explicitWant_;
int AppDomainVerifyMgrClient::convertResultCode_ = 0;
int AppDomainVerifyMgrClient::convertDelaySeconds_ = 0;

AppDomainVerifyMgrClient::AppDomainVerifyMgrClient() {
    taskHandler_ = AAFwk::TaskHandlerWrap::CreateQueueHandler("app_domain_verify_task_queue");
}

AppDomainVerifyMgrClient::~AppDomainVerifyMgrClient() {
    taskHandler_.reset();
}

bool AppDomainVerifyMgrClient::IsAtomicServiceUrl(const std::string& url)
{
    return isAtomicServiceUrlFlag_;
}

void AppDomainVerifyMgrClient::ConvertToExplicitWant(OHOS::AAFwk::Want& implicitWant, sptr<IConvertCallback>& callback)
{
    if (taskHandler_ != nullptr) {
        taskHandler_->SubmitTask([want = implicitWant, callback = callback]() {
            sleep(AppDomainVerifyMgrClient::convertDelaySeconds_);
            AppDomainVerifyMgrClient::explicitWant_.SetUri(want.GetUriString());
            if (callback != nullptr) {
                callback->OnConvert(AppDomainVerifyMgrClient::convertResultCode_,
                    AppDomainVerifyMgrClient::explicitWant_);
            }
        });
    }
}
}  // namespace AppDomainVerify
}  // namespace OHOS