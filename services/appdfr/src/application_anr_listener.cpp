/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "application_anr_listener.h"

#include <sys/time.h>
#include <fstream>
#include "singleton.h"

#include "app_mgr_client.h"
#include "fault_data.h"
#include "hilog_tag_wrapper.h"
#include "hisysevent.h"
#include "parameters.h"
#include "time_util.h"

namespace OHOS {
namespace AAFwk {
namespace {
const bool BETA_VERSION = OHOS::system::GetParameter("const.logsystem.versiontype", "unknown") == "beta";
}
ApplicationAnrListener::ApplicationAnrListener() {}

ApplicationAnrListener::~ApplicationAnrListener() {}

void ApplicationAnrListener::OnAnr(int32_t pid, int32_t eventId) const
{
    std::string faultTimeStr = "\nFault time:" + AbilityRuntime::TimeUtil::FormatTime("%Y/%m/%d-%H:%M:%S") + "\n";
    int32_t ret = HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::AAFWK, "FREEZE_HALF_HIVIEW_LOG",
        HiviewDFX::HiSysEvent::EventType::FAULT, "PID", pid, "PACKAGE_NAME", "", "FAULT_TIME", faultTimeStr);
    TAG_LOGW(AAFwkTag::APPDFR, "hisysevent write FREEZE_HALF_HIVIEW_LOG, pid:%{public}d, packageName:, ret:%{public}d",
        pid, ret);
    AppExecFwk::AppFaultDataBySA faultData;
    std::ifstream statmStream("/proc/" + std::to_string(pid) + "/statm");
    if (statmStream) {
        std::string procStatm;
        std::getline(statmStream, procStatm);
        statmStream.close();
        faultData.procStatm = procStatm;
    }
    faultData.faultType = AppExecFwk::FaultDataType::APP_FREEZE;
    faultData.pid = pid;
    faultData.errorObject.message = faultTimeStr + "User input does not respond!";
    faultData.errorObject.message += (ret == 0) ? "FREEZE_HALF_HIVIEW_LOG write success" : "";
    faultData.errorObject.name = AppExecFwk::AppFreezeType::APP_INPUT_BLOCK;
    faultData.waitSaveState = false;
    faultData.notifyApp = false;
    faultData.forceExit = false;
    faultData.eventId = eventId;
    faultData.schedTime = 0;
    faultData.detectTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance()->NotifyAppFaultBySA(faultData);
}
}  // namespace AAFwk
}  // namespace OHOS
