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

#include "last_exit_detail_info.h"

#include "hilog_tag_wrapper.h"
#include "parcel_macro_base.h"
#include "string_ex.h"

namespace OHOS {
namespace AAFwk {

LastExitDetailInfo::LastExitDetailInfo(const LastExitDetailInfo &other)
{
    pid = other.pid;
    uid = other.uid;
    exitSubReason = other.exitSubReason;
    rss = other.rss;
    pss = other.pss;
    timestamp = other.timestamp;
    processName = other.processName;
    exitMsg = other.exitMsg;
}

LastExitDetailInfo &LastExitDetailInfo::operator=(const LastExitDetailInfo &other)
{
    if (this != &other) {
        pid = other.pid;
        uid = other.uid;
        exitSubReason = other.exitSubReason;
        rss = other.rss;
        pss = other.pss;
        timestamp = other.timestamp;
        processName = other.processName;
        exitMsg = other.exitMsg;
    }
    return *this;
}

bool LastExitDetailInfo::ReadFromParcel(Parcel &parcel)
{
    int32_t pidData;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, pidData);
    pid = pidData;
    int32_t uidData;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, uidData);
    uid = uidData;
    int32_t exitSubReasonData;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, exitSubReasonData);
    exitSubReason = exitSubReasonData;
    int32_t rssData;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, rssData);
    rss = rssData;
    int32_t pssData;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, pssData);
    pss = pssData;
    int64_t timeStampData;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, timeStampData);
    timestamp = timeStampData;
    processName = Str16ToStr8(parcel.ReadString16());
    exitMsg = Str16ToStr8(parcel.ReadString16());
    return true;
}

LastExitDetailInfo *LastExitDetailInfo::Unmarshalling(Parcel &parcel)
{
    LastExitDetailInfo *data = new (std::nothrow) LastExitDetailInfo();
    if (data == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null data");
        return nullptr;
    }

    if (!data->ReadFromParcel(parcel)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "read failed");
        delete data;
        data = nullptr;
    }
    return data;
}

bool LastExitDetailInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, pid);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, uid);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, exitSubReason);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, rss);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, pss);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, timestamp);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(processName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(exitMsg));
    return true;
}
}  // namespace AAFwk
}  // namespace OHOS
