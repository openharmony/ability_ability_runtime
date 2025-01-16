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

#include "process_memory_state.h"

#include "hilog_tag_wrapper.h"
#include "parcel_macro_base.h"

namespace OHOS {
namespace AppExecFwk {

bool ProcessMemoryState::ReadFromParcel(Parcel &parcel)
{
    int32_t pidData;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, pidData);
    pid = static_cast<int32_t>(pidData);
    int32_t rssValueData;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, rssValueData);
    rssValue = static_cast<int32_t>(rssValueData);
    int32_t pssValueData;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, pssValueData);
    pssValue = static_cast<int32_t>(pssValueData);
    return true;
}

ProcessMemoryState *ProcessMemoryState::Unmarshalling(Parcel &parcel)
{
    ProcessMemoryState *state = new (std::nothrow) ProcessMemoryState();
    if (state && !state->ReadFromParcel(parcel)) {
        TAG_LOGW(AAFwkTag::APPMGR, "read from parcel failed");
        delete state;
        state = nullptr;
    }
    return state;
}

bool ProcessMemoryState::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(pid));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(rssValue));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(pssValue));
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
