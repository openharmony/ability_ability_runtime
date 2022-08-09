/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_RUNTIME_EXTRACTOR_H
#define OHOS_ABILITY_RUNTIME_RUNTIME_EXTRACTOR_H

#include "base_extractor.h"

namespace OHOS {
namespace AbilityRuntime {
class RuntimeExtractor : public AppExecFwk::BaseExtractor {
public:
    explicit RuntimeExtractor(const std::string &source);
    virtual ~RuntimeExtractor() override;

    /**
     * @brief Extract the abc file of a hap to dest stream.
     * @param srcPath Indicates the src path of the abc file in hap.
     * @param dest Indicates the obtained std::ostream object.
     * @return Returns true if the Profile is successfully extracted; returns false otherwise.
     */
    bool ExtractABCFile(const std::string& srcPath, std::ostream &dest) const;
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_RUNTIME_EXTRACTOR_H
