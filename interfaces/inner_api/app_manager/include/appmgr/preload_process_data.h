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

#ifndef OHOS_ABILITY_RUNTIME_PRELOAD_PROCESS_DATA_H
#define OHOS_ABILITY_RUNTIME_PRELOAD_PROCESS_DATA_H

#include <string>
#include <unistd.h>

#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {
struct PreloadProcessData : public Parcelable {
    
    virtual bool Marshalling(Parcel &parcel) const override;
    
    static PreloadProcessData *Unmarshalling(Parcel &parcel);
    
    bool ReadFromParcel(Parcel &parcel);

    bool isPreForeground = false;
    pid_t pid = 0;
    int32_t uid = 0;
    std::string bundleName;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_PRELOAD_PROCESS_DATA_H
