/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "fault_data.h"

#include "nlohmann/json.hpp"
#include "string_ex.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
#define RETURN_FALSE_AND_WRITE_LOG_IF_TRUE(expr, log) \
    do { \
        if ((expr)) { \
            TAG_LOGE(AAFwkTag::APPMGR, log); \
            return false; \
        } \
    } while (0)

#define RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(expr, log, arg) \
    do { \
        if ((expr)) { \
            TAG_LOGE(AAFwkTag::APPMGR, log, arg); \
            return false; \
        } \
    } while (0)

bool FaultData::ReadFromParcel(Parcel &parcel)
{
    std::string strValue;
    RETURN_FALSE_AND_WRITE_LOG_IF_TRUE(!parcel.ReadString(strValue), "Name read string failed.");
    errorObject.name = strValue;

    RETURN_FALSE_AND_WRITE_LOG_IF_TRUE(!parcel.ReadString(strValue), "Message read string failed.");
    errorObject.message = strValue;

    RETURN_FALSE_AND_WRITE_LOG_IF_TRUE(!parcel.ReadString(strValue), "Stack read string failed.");
    errorObject.stack = strValue;

    int type = 0;
    RETURN_FALSE_AND_WRITE_LOG_IF_TRUE(!parcel.ReadInt32(type), "FaultType read int32 failed.");
    faultType = static_cast<FaultDataType>(type);

    RETURN_FALSE_AND_WRITE_LOG_IF_TRUE(!parcel.ReadString(strValue), "TimeoutMarkers read string failed.");
    timeoutMarkers = strValue;

    waitSaveState = parcel.ReadBool();
    notifyApp = parcel.ReadBool();
    forceExit = parcel.ReadBool();
    needKillProcess = parcel.ReadBool();
    state = parcel.ReadUint32();
    eventId = parcel.ReadInt32();
    schedTime = parcel.ReadUint64();
    detectTime = parcel.ReadUint64();
    appStatus = parcel.ReadInt32();
    samplerStartTime = parcel.ReadUint64();
    samplerFinishTime = parcel.ReadUint64();
    samplerCount = parcel.ReadInt32();
    pid = parcel.ReadInt32();
    tid = parcel.ReadInt32();
    stuckTimeout = parcel.ReadUint32();
    if (parcel.ReadBool()) {
        token = (static_cast<MessageParcel*>(&parcel))->ReadRemoteObject();
    }

    RETURN_FALSE_AND_WRITE_LOG_IF_TRUE(!parcel.ReadString(strValue), "AppfreezeInfo read string failed.");
    appfreezeInfo = strValue;
    return ReadContent(parcel);
}

bool FaultData::ReadContent(Parcel &parcel)
{
    std::string strValue;
    RETURN_FALSE_AND_WRITE_LOG_IF_TRUE(!parcel.ReadString(strValue), "AppRunningUniqueId read string failed.");
    appRunningUniqueId = strValue;

    RETURN_FALSE_AND_WRITE_LOG_IF_TRUE(!parcel.ReadString(strValue), "ProcStatm read string failed.");
    procStatm = strValue;

    isInForeground = parcel.ReadBool();
    isEnableMainThreadSample = parcel.ReadBool();
    return true;
}

FaultData *FaultData::Unmarshalling(Parcel &parcel)
{
    FaultData *info = new FaultData();
    if (!info->ReadFromParcel(parcel)) {
        delete info;
        info = nullptr;
    }
    return info;
}

bool FaultData::WriteContent(Parcel &parcel) const
{
    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteUint32(stuckTimeout),
        "stuckTimeout [%{public}u] write uint32 failed.", stuckTimeout
    );

    if (token == nullptr) {
        RETURN_FALSE_AND_WRITE_LOG_IF_TRUE(!parcel.WriteBool(false), "Token falge [false] write bool failed.");
    } else {
        if (!parcel.WriteBool(true) || !(static_cast<MessageParcel*>(&parcel))->WriteRemoteObject(token)) {
            TAG_LOGE(AAFwkTag::APPMGR, "Token falge [true] write bool failed.");
            return false;
        }
    }

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteString(appfreezeInfo),
        "AppfreezeInfo [%{public}s] write string failed.", appfreezeInfo.c_str()
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteString(appRunningUniqueId),
        "AppRunningUniqueId [%{public}s] write string failed.", appRunningUniqueId.c_str()
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteString(procStatm),
        "ProcStatm [%{public}s] write string failed.", procStatm.c_str()
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteBool(isInForeground),
        "InForeground [%{public}d] write bool failed.", isInForeground
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteBool(isEnableMainThreadSample),
        "isEnableMainThreadSample [%{public}d] write bool failed.", isEnableMainThreadSample
    );
    return true;
}

bool FaultData::Marshalling(Parcel &parcel) const
{
    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteString(errorObject.name),
        "Name [%{public}s] write string failed.", errorObject.name.c_str()
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteString(errorObject.message),
        "Message [%{public}s] write string failed.", errorObject.message.c_str()
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteString(errorObject.stack),
        "Stack [%{public}s] write string failed.", errorObject.stack.c_str()
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteInt32(static_cast<int32_t>(faultType)),
        "FaultType [%{public}d] write int32 failed.", static_cast<int32_t>(faultType)
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteString(timeoutMarkers),
        "TimeoutMarkers [%{public}s] write string failed.", timeoutMarkers.c_str()
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteBool(waitSaveState),
        "WaitSaveState [%{public}s] write bool failed.", waitSaveState ? "true" : "false"
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteBool(notifyApp),
        "NotifyApp [%{public}s] write bool failed.", notifyApp ? "true" : "false"
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteBool(forceExit),
        "ForceExit [%{public}s] write bool failed.", forceExit ? "true" : "false"
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteBool(needKillProcess),
        "needKillProcess [%{public}s] write bool failed.", needKillProcess ? "true" : "false"
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteUint32(state),
        "State [%{public}u] write uint32 failed.", state
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteInt32(eventId),
        "EventId [%{public}u] write int32 failed.", eventId
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteUint64(schedTime),
        "SchedTime [%{public}" PRIu64 "] write uint64 failed.", schedTime
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteUint64(detectTime),
        "DetectTime [%{public}" PRIu64 "] write uint64 failed.", detectTime
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteInt32(appStatus),
        "AppStatus [%{public}d] write int32 failed.", appStatus
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteUint64(samplerStartTime),
        "SamplerStartTime [%{public}" PRIu64 "] write uint64 failed.", samplerStartTime
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteUint64(samplerFinishTime),
        "SamplerFinishTime [%{public}" PRIu64"] write uint64 failed.", samplerFinishTime
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteInt32(samplerCount),
        "SamplerCount [%{public}d] write int32 failed.", samplerCount
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteInt32(pid),
        "Pid [%{public}u] write int32 failed.", pid
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteInt32(tid),
        "Tid [%{public}u] write int32 failed.", tid
    );

    return WriteContent(parcel);
}

bool AppFaultDataBySA::ReadFromParcel(Parcel &parcel)
{
    std::string strValue;
    RETURN_FALSE_AND_WRITE_LOG_IF_TRUE(!parcel.ReadString(strValue), "Name read string failed.");
    errorObject.name = strValue;

    RETURN_FALSE_AND_WRITE_LOG_IF_TRUE(!parcel.ReadString(strValue), "Message read string failed.");
    errorObject.message = strValue;

    RETURN_FALSE_AND_WRITE_LOG_IF_TRUE(!parcel.ReadString(strValue), "Stack read string failed.");
    errorObject.stack = strValue;

    int type = 0;
    RETURN_FALSE_AND_WRITE_LOG_IF_TRUE(!parcel.ReadInt32(type), "Type read int32 failed.");
    faultType = static_cast<FaultDataType>(type);

    RETURN_FALSE_AND_WRITE_LOG_IF_TRUE(!parcel.ReadInt32(pid), "Pid read int32 failed.");

    RETURN_FALSE_AND_WRITE_LOG_IF_TRUE(!parcel.ReadString(strValue), "TimeoutMarkers read string failed.");
    timeoutMarkers = strValue;

    waitSaveState = parcel.ReadBool();
    notifyApp = parcel.ReadBool();
    forceExit = parcel.ReadBool();
    needKillProcess = parcel.ReadBool();
    state = parcel.ReadUint32();
    eventId = parcel.ReadInt32();
    schedTime = parcel.ReadUint64();
    detectTime = parcel.ReadUint64();
    appStatus = parcel.ReadInt32();
    if (parcel.ReadBool()) {
        token = (static_cast<MessageParcel*>(&parcel))->ReadRemoteObject();
    }

    RETURN_FALSE_AND_WRITE_LOG_IF_TRUE(!parcel.ReadString(strValue), "AppfreezeInfo read string failed.");
    appfreezeInfo = strValue;
    return ReadContent(parcel);
}

bool AppFaultDataBySA::ReadContent(Parcel &parcel)
{
    std::string strValue;
    RETURN_FALSE_AND_WRITE_LOG_IF_TRUE(!parcel.ReadString(strValue), "AppRunningUniqueId read string failed.");
    appRunningUniqueId = strValue;

    RETURN_FALSE_AND_WRITE_LOG_IF_TRUE(!parcel.ReadString(strValue), "ProcStatm read string failed.");
    procStatm = strValue;
    isInForeground = parcel.ReadBool();
    isEnableMainThreadSample = parcel.ReadBool();
    return true;
}

AppFaultDataBySA *AppFaultDataBySA::Unmarshalling(Parcel &parcel)
{
    AppFaultDataBySA *info = new AppFaultDataBySA();
    if (!info->ReadFromParcel(parcel)) {
        delete info;
        info = nullptr;
    }
    return info;
}

bool AppFaultDataBySA::WriteContent(Parcel &parcel) const
{
    if (token == nullptr) {
        RETURN_FALSE_AND_WRITE_LOG_IF_TRUE(!parcel.WriteBool(false), "Token falge [false] write bool failed.");
    } else {
        if (!parcel.WriteBool(true) || !(static_cast<MessageParcel*>(&parcel))->WriteRemoteObject(token)) {
            TAG_LOGE(AAFwkTag::APPMGR, "Token falge [true] write bool failed.");
            return false;
        }
    }

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteString(appfreezeInfo),
        "AppfreezeInfo [%{public}s] write string failed.", appfreezeInfo.c_str()
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteString(appRunningUniqueId),
        "AppRunningUniqueId [%{public}s] write string failed.", appRunningUniqueId.c_str()
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteString(procStatm),
        "ProcStatm [%{public}s] write string failed.", procStatm.c_str()
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteBool(isInForeground),
        "InForeground [%{public}d] write bool failed.", isInForeground
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteBool(isEnableMainThreadSample),
        "isEnableMainThreadSample [%{public}d] write bool failed.", isEnableMainThreadSample
    );
    return true;
}

bool AppFaultDataBySA::Marshalling(Parcel &parcel) const
{
    if (!WriteErrorObject(parcel)) {
        return false;
    }

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteInt32(static_cast<int32_t>(faultType)),
        "FaultType [%{public}d] write int32 failed.", static_cast<int32_t>(faultType)
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteInt32(pid),
        "Pid [%{public}d] write int32 failed.", static_cast<int32_t>(pid)
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteString(timeoutMarkers),
        "TimeoutMarkers [%{public}s] write string failed.", timeoutMarkers.c_str()
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteBool(waitSaveState),
        "WaitSaveState [%{public}s] write bool failed.", waitSaveState ? "true" : "false"
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteBool(notifyApp),
        "NotifyApp [%{public}s] write bool failed.", notifyApp ? "true" : "false"
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteBool(forceExit),
        "ForceExit [%{public}s] write bool failed.", forceExit ? "true" : "false"
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteBool(needKillProcess),
        "needKillProcess [%{public}s] write bool failed.", needKillProcess ? "true" : "false"
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteUint32(state),
        "State [%{public}u] write uint32 failed.", state
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteInt32(eventId),
        "EventId [%{public}u] write int32 failed.", eventId
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteUint64(schedTime),
        "SchedTime [%{public}" PRIu64 "] write uint64 failed.", schedTime
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteUint64(detectTime),
        "DetectTime [%{public}" PRIu64 "] write uint64 failed.", detectTime
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteInt32(appStatus),
        "AppStatus [%{public}d] write int32 failed.", appStatus
    );

    return WriteContent(parcel);
}

bool AppFaultDataBySA::WriteErrorObject(Parcel &parcel) const
{
    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteString(errorObject.name),
        "Name [%{public}s] write string failed.", errorObject.name.c_str()
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteString(errorObject.message),
        "Message [%{public}s] write string failed.", errorObject.message.c_str()
    );

    RETURN_FALSE_AND_WRITE_LOG_WITH_ONE_ARG_IF_TRUE(!parcel.WriteString(errorObject.stack),
        "Stack [%{public}s] write string failed.", errorObject.stack.c_str()
    );
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS