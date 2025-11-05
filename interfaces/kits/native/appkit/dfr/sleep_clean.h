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

#ifndef OHOS_ABILITY_RUNTIME_SLEEPCLEAN_H
#define OHOS_ABILITY_RUNTIME_SLEEPCLEAN_H

#include <memory>

#include "ability_record_mgr.h"
#include "assert_fault_task_thread.h"
#include "application_impl.h"
#include "fault_data.h"
#include "ohos_application.h"

namespace OHOS {
namespace AppExecFwk {
const size_t SLEEP_CLEAN_DELAY_TIME = 2000;    //2000ms

class SleepClean {
public:
    SleepClean() {}
    ~SleepClean() {}

    bool HandleSleepClean(const FaultData &faultData, const std::shared_ptr<OHOSApplication> &application);

    static SleepClean &GetInstance();

private:
    size_t GetHeapSize(const std::shared_ptr<OHOSApplication> &application);
    bool HandleAppSaveIfHeap(const std::shared_ptr<OHOSApplication> &application);
    void HandleAppSaveState(const std::shared_ptr<OHOSApplication> &application);
};
}   //namespace AppExecFwk
}   //namespace OHOS


#endif  //OHOS_ABILITY_RUNTIME_SLEEPCLEAN_H
