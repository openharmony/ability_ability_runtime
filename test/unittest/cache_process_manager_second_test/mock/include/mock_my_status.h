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

#ifndef MOCK_MY_STATUS_H
#define MOCK_MY_STATUS_H
#include "bundle_mgr_helper.h"
#include "remote_client_manager.h"
#include "app_running_record.h"
#include "iservice_registry.h"
#include "singleton.h"
#include "system_ability_definition.h"
#include "user_record_manager.h"

#include <mutex>
#include "hilog_tag_wrapper.h"
namespace OHOS {
namespace AAFwk {
class MyStatus {
public:
    static MyStatus& GetInstance();
    ~MyStatus() = default;

    // ResSchedUtil
    bool isShouldKillProcess_ = false;

    // app running record
    int32_t getAppIndex_ = 0;
    bool isKeepAliveApp_ = false;
    int32_t setProcessCacheBlockedTimes_ = 0;
private:
    MyStatus() = default;
};
}  // namespace AAFwk
}  // namespace OHOS
#endif // MOCK_MY_STATUS_H