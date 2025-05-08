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

#include "process_bind_data.h"

#include "hilog_tag_wrapper.h"
#include "parcel_macro_base.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool ProcessBindData::Marshalling(Parcel &parcel) const
{
    return (parcel.WriteString(bundleName) && parcel.WriteInt32(pid) && parcel.WriteInt32(uid) &&
            parcel.WriteBool(isKeepAlive) && parcel.WriteInt32(static_cast<int32_t>(processType)) &&
            parcel.WriteInt32(static_cast<int32_t>(extensionType)) && parcel.WriteInt32(callerPid) &&
            parcel.WriteInt32(callerUid) && parcel.WriteString(callerBundleName) && parcel.WriteInt32(bindingRelation));
}

bool ProcessBindData::ReadFromParcel(Parcel &parcel)
{
    bundleName = parcel.ReadString();
    pid = parcel.ReadInt32();
    uid = parcel.ReadInt32();
    isKeepAlive = parcel.ReadBool();
    processType = static_cast<ProcessType>(parcel.ReadInt32());
    extensionType = static_cast<ExtensionAbilityType>(parcel.ReadInt32());
    callerPid = parcel.ReadInt32();
    callerUid = parcel.ReadInt32();
    callerBundleName = parcel.ReadString();
    bindingRelation = parcel.ReadInt32();
    return true;
}

ProcessBindData *ProcessBindData::Unmarshalling(Parcel &parcel)
{
    ProcessBindData *processBindData = new (std::nothrow) ProcessBindData();
    if (processBindData && !processBindData->ReadFromParcel(parcel)) {
        TAG_LOGW(AAFwkTag::APPMGR, "processBindData failed, because ReadFromParcel failed");
        delete processBindData;
        processBindData = nullptr;
    }
    return processBindData;
}
} // namespace AppExecFwk
} // namespace OHOS
 