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

#include "app_cjheap_mem_info.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
bool CjHeapDumpInfo::Marshalling(Parcel &parcel) const
{
    return (parcel.WriteUint32(pid) && parcel.WriteBool(needGc) && parcel.WriteBool(needSnapshot));
}

CjHeapDumpInfo *CjHeapDumpInfo::Unmarshalling(Parcel &parcel)
{
    CjHeapDumpInfo *info = new (std::nothrow) CjHeapDumpInfo();
    if (info == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "info nullptr");
        return nullptr;
    }
    info->pid = parcel.ReadUint32();
    info->needGc = parcel.ReadBool();
    info->needSnapshot = parcel.ReadBool();
    return info;
}
} // namespace AppExecFwk
} // namespace OHOS
