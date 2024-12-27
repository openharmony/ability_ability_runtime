/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_IPC_CAPACITY_WRAP_H
#define OHOS_ABILITY_RUNTIME_IPC_CAPACITY_WRAP_H

#include "ipc_types.h"

namespace OHOS {
namespace AAFwk {
namespace {
constexpr int32_t MAX_IPC_CAPACITY_FOR_WANT = 216 * 1024;
}

static inline void ExtendMaxIpcCapacityForInnerWant(MessageParcel &parcel)
{
    if ((parcel).GetMaxCapacity() < MAX_IPC_CAPACITY_FOR_WANT) {
        (parcel).SetMaxCapacity(MAX_IPC_CAPACITY_FOR_WANT);
    }
}

}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_IPC_CAPACITY_WRAP_H
