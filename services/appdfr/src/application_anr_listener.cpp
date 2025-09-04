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
#include "backtrace_local.h"
#include "fault_data.h"
#include "hilog_tag_wrapper.h"
#include "hisysevent.h"
#include "time_util.h"
#include "parameters.h"

namespace OHOS {
namespace AAFwk {
namespace {
const bool BETA_VERSION = OHOS::system::GetParameter("const.logsystem.versiontype", "unknown") == "beta";
}
ApplicationAnrListener::ApplicationAnrListener() {}

ApplicationAnrListener::~ApplicationAnrListener() {}

void ApplicationAnrListener::OnAnr(int32_t pid, int32_t eventId) const
{
    if (!BETA_VERSION) {
        int32_t ret = HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::AAFWK, "HIVIEW_HALF_FREEZE_LOG",
            HiviewDFX::HiSysEvent::EventType::FAULT, "PID", pid, "PACKAGE_NAME", "");
        TAG_LOGW(AAFwkTag::APPDFR, "hisysevent write HIVIEW_HALF_FREEZE_LOG, pid:%{public}d, packageName:,"
            " ret:%{public}d", pid, ret);
    }
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
    faultData.errorObject.message = "User input does not respond!";
    faultData.errorObject.stack =  "\nDump tid stack start time: " +
        AbilityRuntime::TimeUtil::DefaultCurrentTimeStr() + "\n";
    std::string stack;
    if (!HiviewDFX::GetBacktraceStringByTidWithMix(stack, pid, 0, true)) {
        stack = "Failed to dump stacktrace for " + std::to_string(pid) + "\n" + stack;
    }
    faultData.errorObject.stack += stack + "\nDump tid stack end time: " +
        AbilityRuntime::TimeUtil::DefaultCurrentTimeStr() + "\n";
    faultData.errorObject.name = AppExecFwk::AppFreezeType::APP_INPUT_BLOCK;
    faultData.waitSaveState = false;
    faultData.notifyApp = false;
    faultData.forceExit = false;
    faultData.eventId = eventId;
    faultData.schedTime = 0;
    faultData.detectTime = AbilityRuntime::TimeUtil::CurrentTimeMillis();
    DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance()->NotifyAppFaultBySA(faultData);
}
}  // namespace AAFwk
}  // namespace OHOS
