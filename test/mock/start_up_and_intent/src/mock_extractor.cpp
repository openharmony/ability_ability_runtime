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

#include "extractor.h"

namespace OHOS {
namespace AbilityBase {
Extractor::Extractor(const std::string &source)
{
    hapPath_ = source;
}

bool Extractor::ExtractByName(const std::string &fileName, std::ostream &dest)
{
    return true;
}

bool Extractor::ExtractToBufByName(const std::string &fileName, std::unique_ptr<uint8_t[]> &dataPtr,
    size_t &len) const
{
    return true;
}

std::shared_ptr<Extractor> ExtractorUtil::GetExtractor(const std::string &hapPath, bool &newCreate, bool cache)
{
    std::shared_ptr<Extractor> extractorPtr = std::make_shared<Extractor>("test");
    return extractorPtr;
}

std::string ExtractorUtil::GetLoadFilePath(const std::string &hapPath)
{
    return "";
}
}
}