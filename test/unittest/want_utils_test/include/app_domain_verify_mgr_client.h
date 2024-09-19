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

#ifndef APP_DOMAIN_VERIFY_MGR_CLIENT_H
#define APP_DOMAIN_VERIFY_MGR_CLIENT_H

#include <memory>
#include "singleton.h"

#include "i_convert_callback.h"
#include "refbase.h"
#include "task_handler_wrap.h"

namespace OHOS {
namespace AppDomainVerify {
class AppDomainVerifyMgrClient : public DelayedSingleton<AppDomainVerifyMgrClient> {
    DECLARE_DELAYED_SINGLETON(AppDomainVerifyMgrClient);

public:
    DISALLOW_COPY_AND_MOVE(AppDomainVerifyMgrClient);
    static bool isAtomicServiceUrlFlag_;
    static AAFwk::Want explicitWant_;
    static int convertResultCode_;
    /**
     * IsAtomicServiceUrl
     * @descrition check input url is atomic service or not.
     * @param url input url to check.
     * @return bool is atomic service or not.
     */
    bool IsAtomicServiceUrl(const std::string& url);

    /**
     * ConvertToExplicitWant
     * @descrition convert implicit want to explicit want.
     * @param implicitWant implicit want to convert.
     * @param callback callback when convert finish.
     */
    void ConvertToExplicitWant(OHOS::AAFwk::Want& implicitWant, sptr<IConvertCallback>& callback);

private:
    std::shared_ptr<AAFwk::TaskHandlerWrap> taskHandler_;
};
}  // namespace AppDomainVerify
}  // namespace OHOS

#endif