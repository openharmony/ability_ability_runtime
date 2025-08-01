/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "process_data.h"

#include "hilog_tag_wrapper.h"
#include "parcel_macro_base.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool ProcessData::Marshalling(Parcel &parcel) const
{
    return (parcel.WriteString(bundleName) && parcel.WriteInt32(pid) &&
        parcel.WriteInt32(uid) && parcel.WriteInt32(hostPid) && parcel.WriteInt32(gpuPid) &&
        parcel.WriteInt32(static_cast<int32_t>(state)) && parcel.WriteBool(isContinuousTask) &&
        parcel.WriteBool(isKeepAlive) && parcel.WriteBool(isFocused) && parcel.WriteInt32(requestProcCode) &&
        parcel.WriteInt32(processChangeReason) && parcel.WriteString(processName) &&
        parcel.WriteInt32(static_cast<int32_t>(processType)) && parcel.WriteInt32(static_cast<int32_t>(extensionType))
        && parcel.WriteInt32(renderUid) && parcel.WriteUint32(accessTokenId) &&
        parcel.WriteBool(isTestMode) && parcel.WriteInt32(exitReason) && parcel.WriteString16(Str8ToStr16(exitMsg)) &&
        parcel.WriteInt32(childUid) && parcel.WriteBool(isPreload)  && parcel.WriteBool(isPreloadModule) &&
        parcel.WriteInt32(callerPid) && parcel.WriteInt32(callerUid) && parcel.WriteString(killReason) &&
        parcel.WriteBool(isFromWindowFocusChanged));
}

bool ProcessData::ReadFromParcel(Parcel &parcel)
{
    bundleName = parcel.ReadString();
    pid = parcel.ReadInt32();
    uid = parcel.ReadInt32();
    hostPid = parcel.ReadInt32();
    gpuPid = parcel.ReadInt32();
    state = static_cast<AppProcessState>(parcel.ReadInt32());
    isContinuousTask = parcel.ReadBool();
    isKeepAlive = parcel.ReadBool();
    isFocused = parcel.ReadBool();
    requestProcCode = parcel.ReadInt32();
    processChangeReason = parcel.ReadInt32();
    processName = parcel.ReadString();
    processType = static_cast<ProcessType>(parcel.ReadInt32());
    extensionType = static_cast<ExtensionAbilityType>(parcel.ReadInt32());
    renderUid = parcel.ReadInt32();
    accessTokenId = parcel.ReadUint32();
    isTestMode = parcel.ReadBool();
    exitReason = parcel.ReadInt32();
    exitMsg = Str16ToStr8(parcel.ReadString16());
    childUid = parcel.ReadInt32();
    isPreload = parcel.ReadBool();
    isPreloadModule = parcel.ReadBool();
    callerPid = parcel.ReadInt32();
    callerUid = parcel.ReadInt32();
    killReason = parcel.ReadString();
    isFromWindowFocusChanged = parcel.ReadBool();
    return true;
}

ProcessData *ProcessData::Unmarshalling(Parcel &parcel)
{
    ProcessData *processData = new (std::nothrow) ProcessData();
    if (processData && !processData->ReadFromParcel(parcel)) {
        TAG_LOGW(AAFwkTag::APPMGR, "processData failed, because ReadFromParcel failed");
        delete processData;
        processData = nullptr;
    }
    return processData;
}
}  // namespace AppExecFwk
}  // namespace OHOS
