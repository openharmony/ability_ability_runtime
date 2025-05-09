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

#ifndef OHOS_ABILITY_RUNTIME_START_WINDOW_OPTION_H
#define OHOS_ABILITY_RUNTIME_START_WINDOW_OPTION_H

#include "parcel.h"

namespace OHOS {
namespace Media {
class PixelMap;
}
namespace AAFwk {
class StartWindowOption final : public Parcelable {
public:
    StartWindowOption() = default;
    ~StartWindowOption() = default;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static StartWindowOption *Unmarshalling(Parcel &parcel);

    bool hasStartWindow = false;
    std::shared_ptr<Media::PixelMap> startWindowIcon = nullptr;
    std::string startWindowBackgroundColor;
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_START_WINDOW_OPTION_H
