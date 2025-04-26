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

#ifndef MOCK_OHOS_ABILITY_RUNTIME_EXTRACTOR_H
#define MOCK_OHOS_ABILITY_RUNTIME_EXTRACTOR_H

#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>
 
namespace OHOS {
namespace AbilityBase {

class Extractor {
public:
    explicit Extractor(const std::string &source);

    bool ExtractByName(const std::string &fileName, std::ostream &dest);
    bool ExtractToBufByName(const std::string &fileName, std::unique_ptr<uint8_t[]> &dataPtr, size_t &len) const;
    std::string hapPath_;
};
 
class ExtractorUtil {
public:
    static std::string GetLoadFilePath(const std::string &hapPath);
    static std::shared_ptr<Extractor> GetExtractor(const std::string &hapPath, bool &newCreate, bool cache = false);
};
}  // namespace AbilityBase
}  // namespace OHOS
#endif
 