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

#ifndef MOCK_OHOS_ABILITY_BASE_URI_H
#define MOCK_OHOS_ABILITY_BASE_URI_H

#include <string>
#include <vector>
#include "parcel.h"

namespace OHOS {
class Uri : public RefBase {
public:
    explicit Uri(const std::string& uriString) {}
    Uri() {}
    std::string GetScheme()
    {
        return "";
    }

    void GetPathSegments(std::vector<std::string>& segments) {}

    std::string ToString() const
    {
        return "";
    }

    bool operator==(const Uri& other) const
    {
        return false;
    }
};
} // namespace OHOS
#endif