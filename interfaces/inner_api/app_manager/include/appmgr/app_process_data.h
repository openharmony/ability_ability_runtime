/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_APP_PROCESS_DATA_H
#define OHOS_ABILITY_RUNTIME_APP_PROCESS_DATA_H

#include <sys/types.h>

#include "parcel.h"

#include "app_mgr_constants.h"

namespace OHOS {
namespace AppExecFwk {
struct AppData {
    std::string appName;
    int32_t uid;
};

struct AppProcessData : public Parcelable {
    /**
     * @brief read this Sequenceable object from a Parcel.
     *
     * @param inParcel Indicates the Parcel object into which the Sequenceable object has been marshaled.
     * @return Returns true if read successed; returns false otherwise.
     */
    bool ReadFromParcel(Parcel &parcel);

    /**
     * @brief Marshals this Sequenceable object into a Parcel.
     *
     * @param outParcel Indicates the Parcel object to which the Sequenceable object will be marshaled.
     */
    virtual bool Marshalling(Parcel &parcel) const override;

    /**
     * @brief Unmarshals this Sequenceable object from a Parcel.
     *
     * @param inParcel Indicates the Parcel object into which the Sequenceable object has been marshaled.
     */
    static AppProcessData *Unmarshalling(Parcel &parcel);

    bool isFocused = false;
    int32_t appIndex = 0;
    ApplicationState appState = ApplicationState::APP_STATE_CREATE;
    pid_t pid = 0;
    std::vector<AppData> appDatas;
    std::vector<int32_t> renderPids;
    std::string processName;
    std::string instanceKey = "";
    std::string bundleName = "";
    bool isFromWindowFocusChanged = false;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_APP_PROCESS_DATA_H
