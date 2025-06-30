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
#ifndef MOCK_OHOS_ABILITY_BASE_WANT_PARAMS_H
#define MOCK_OHOS_ABILITY_BASE_WANT_PARAMS_H

#include <unistd.h>

#include "parcel.h"
#include "refbase.h"
#include "string_wrapper.h"

namespace OHOS {
namespace AAFwk {
enum ScreenMode : int8_t {
    IDLE_SCREEN_MODE = -1,
    JUMP_SCREEN_MODE = 0,
    EMBEDDED_FULL_SCREEN_MODE = 1,
    EMBEDDED_HALF_SCREEN_MODE = 2
};
constexpr const char* SCREEN_MODE_KEY = "ohos.extra.param.key.showMode";

class WantParams final : public Parcelable {
public:
    WantParams() = default;
    WantParams(const WantParams &wantParams) {}
    ~WantParams() {}
    WantParams &operator=(const WantParams &other)
    {
        return *this;
    }

    void SetParam(const std::string &key, int value) {}

    std::string GetStringParam(const std::string& key) const
    {
        return "";
    }

    int Size() const
    {
        return 0;
    }

    virtual bool Marshalling(Parcel &parcel) const
    {
        return false;
    }

    static WantParams *Unmarshalling(Parcel &parcel, int depth = 1)
    {
        return nullptr;
    }
};
}  // namespace AAFwk
}  // namespace OHOS
#endif
