/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_JS_ENVIRONMENT_SOURCE_MAP_H
#define OHOS_ABILITY_JS_ENVIRONMENT_SOURCE_MAP_H

#include <cstring>
#include <fstream>
#include <limits.h>
#include <mutex>
#include <unordered_map>
#include <utility>
#include <thread>
#include <vector>

namespace OHOS {
namespace JsEnv {
namespace {
const std::string NOT_FOUNDMAP = "Cannot get SourceMap info, dump raw stack:\n";
}
using ErrorPos = std::pair<uint32_t, uint32_t>;
struct SourceMapInfo {
    int32_t beforeRow = 0;
    int32_t beforeColumn = 0;
    int32_t afterRow = 0;
    int32_t afterColumn = 0;
};

struct MappingInfo {
    int32_t row = 0;
    int32_t col = 0;
    std::string sources;
};

class SourceMapData final {
public:
    SourceMapData() = default;
    ~SourceMapData() = default;

    SourceMapInfo nowPos_;
    std::string packageName_;
    bool isPackageInfo_ = false;
    std::string sources_;
    std::vector<std::string> mappings_;
    std::vector<SourceMapInfo> afterPos_;

    inline SourceMapData GetSourceMapData() const
    {
        return *this;
    }
};

using ReadSourceMapCallback = std::function<bool(const std::string& hapPath,
    const std::string& sourceMapPath, std::string& content)>;
using GetHapPathCallback = std::function<void(const std::string &bundleName, std::vector<std::string> &hapList)>;
class SourceMap final {
public:
    SourceMap() = default;
    ~SourceMap() = default;

    void Init(bool& hasFile, const std::string& hapPath);
    std::string TranslateBySourceMap(const std::string& stackStr);
    bool TranslateUrlPositionBySourceMap(std::string& url, int& line, int& column, std::string& packageName);
    static ErrorPos GetErrorPos(const std::string& rawStack);
    static void RegisterReadSourceMapCallback(ReadSourceMapCallback readFunc);
    static bool ReadSourceMapData(const std::string& hapPath, const std::string& sourceMapPath, std::string& content);
    static void RegisterGetHapPathCallback(GetHapPathCallback getFunc);
    static void GetHapPath(const std::string &bundleName, std::vector<std::string> &hapList);
    bool GetLineAndColumnNumbers(int& line, int& column, SourceMapData& targetMap, std::string& url,
                                 std::string& packageName);
    static void ExtractStackInfo(const std::string& stackStr, std::vector<std::string>& res);
    void SplitSourceMap(const std::string& sourceMapData);
    
private:
    void ExtractSourceMapData(const std::string& allmappings, std::shared_ptr<SourceMapData>& curMapData);
    void ExtractKeyInfo(const std::string& sourceMap, std::vector<std::string>& sourceKeyInfo);
    std::vector<std::string> HandleMappings(const std::string& mapping);
    bool VlqRevCode(const std::string& vStr, std::vector<int32_t>& ans);
    MappingInfo Find(int32_t row, int32_t col, const SourceMapData& targetMap, const std::string& key);
    void GetPosInfo(const std::string& temp, int32_t start, std::string& line, std::string& column);
    std::string GetSourceInfo(const std::string& line, const std::string& column,
                              const SourceMapData& targetMap, const std::string& key);
    static void GetPackageName(const SourceMapData& targetMap, std::string& packageName);

private:
    static ReadSourceMapCallback readSourceMapFunc_;
    static std::mutex sourceMapMutex_;
    static GetHapPathCallback getHapPathFunc_;
    std::unordered_map<std::string, std::shared_ptr<SourceMapData>> sourceMaps_;
};
} // namespace JsEnv
} // namespace OHOS

#endif // OHOS_ABILITY_JS_ENVIRONMENT_SOURCE_MAP_H
