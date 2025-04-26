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

#include "source_map.h"

#include <cerrno>
#include <climits>
#include <cstdlib>
#include <fstream>
#include <vector>
#include <sstream>
#include <unistd.h>

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace JsEnv {
namespace {
constexpr char DELIMITER_COMMA = ',';
constexpr char DELIMITER_SEMICOLON = ';';
constexpr char DOUBLE_SLASH = '\\';
constexpr char WEBPACK[] = "webpack:///";
constexpr int32_t INDEX_ONE = 1;
constexpr int32_t INDEX_TWO = 2;
constexpr int32_t INDEX_THREE = 3;
constexpr int32_t INDEX_FOUR = 4;
constexpr int32_t ANS_MAP_SIZE = 5;
constexpr int32_t DIGIT_NUM = 64;
const std::string MEGER_SOURCE_MAP_PATH = "ets/sourceMaps.map";
const std::string FLAG_SOURCES = "    \"sources\":";
const std::string FLAG_MAPPINGS = "    \"mappings\": \"";
const std::string FLAG_ENTRY_PACKAGE_INFO = "    \"entry-package-info\": \"";
const std::string FLAG_PACKAGE_INFO = "    \"package-info\": \"";
const std::string FLAG_END = "  }";
const std::string FLAG_CLOSE_BRACE = ")";
const std::string FLAG_OPEN_BRACE = "(";
static constexpr size_t FLAG_MAPPINGS_LEN = 17;
static constexpr size_t FLAG_ENTRY_PACKAGE_INFO_SIZE = 27;
static constexpr size_t FLAG_PACKAGE_INFO_SIZE = 21;
static constexpr size_t REAL_URL_INDEX = 3;
static constexpr size_t REAL_SOURCE_INDEX = 7;
} // namespace
ReadSourceMapCallback SourceMap::readSourceMapFunc_ = nullptr;
GetHapPathCallback SourceMap::getHapPathFunc_ = nullptr;
std::mutex SourceMap::sourceMapMutex_;

int32_t StringToInt(const std::string& value)
{
    errno = 0;
    char* pEnd = nullptr;
    int64_t result = std::strtol(value.c_str(), &pEnd, 10);
    if (pEnd == value.c_str() || (result < INT_MIN || result > INT_MAX) || errno == ERANGE) {
        return 0;
    } else {
        return result;
    }
}

uint32_t Base64CharToInt(char charCode)
{
    if ('A' <= charCode && charCode <= 'Z') {
        // 0 - 25: ABCDEFGHIJKLMNOPQRSTUVWXYZ
        return charCode - 'A';
    } else if ('a' <= charCode && charCode <= 'z') {
        // 26 - 51: abcdefghijklmnopqrstuvwxyz
        return charCode - 'a' + 26;
    } else if ('0' <= charCode && charCode <= '9') {
        // 52 - 61: 0123456789
        return charCode - '0' + 52;
    } else if (charCode == '+') {
        // 62: +
        return 62;
    } else if (charCode == '/') {
        // 63: /
        return 63;
    }
    return DIGIT_NUM;
};

bool StringStartWith(const std::string& str, const std::string& startStr)
{
    size_t startStrLen = startStr.length();
    return ((str.length() >= startStrLen) && (str.compare(0, startStrLen, startStr) == 0));
}

void SourceMap::Init(bool& hasFile, const std::string& hapPath)
{
    std::string sourceMapData;
    if (ReadSourceMapData(hapPath, MEGER_SOURCE_MAP_PATH, sourceMapData)) {
        hasFile = true;
    }
    SplitSourceMap(sourceMapData);
}

std::string SourceMap::ExtractFileName(const std::string& str)
{
    // at funcName (@param:version|url:line:column)
    // Find the position of the last colon in the character string.
    size_t lastColon = str.rfind(':');
    if (lastColon != std::string::npos) {
        // Find the position of the last but one colon in the character string.
        size_t prevColon = str.rfind(':', lastColon - 1);
        if (prevColon != std::string::npos) {
            // Find the position of the first brace in the character string.
            size_t openBrace = str.find(FLAG_OPEN_BRACE);
            if (openBrace != std::string::npos) {
                // Extract the character string between colons and braces as the file name.
                return str.substr(openBrace + 1, prevColon - openBrace - 1);
            }
        }
    }
    return str;
}

std::string SourceMap::TranslateBySourceMap(const std::string& stackStr)
{
    std::string ans = "";

    // find per line of stack
    std::vector<std::string> res;
    ExtractStackInfo(stackStr, res);

    // collect error info first
    for (uint32_t i = 0; i < res.size(); i++) {
        std::string temp = res[i];
        std::string key = ExtractFileName(temp);
        auto closeBracePos = static_cast<int32_t>(temp.find(FLAG_CLOSE_BRACE));
        auto openBracePos = static_cast<int32_t>(temp.find(FLAG_OPEN_BRACE));
        std::string line;
        std::string column;
        GetPosInfo(temp, closeBracePos, line, column);
        if (line.empty() || column.empty()) {
            TAG_LOGW(AAFwkTag::JSENV, "the stack without line info");
            break;
        }
        std::string sourceInfo;
        auto iter = sourceMaps_.find(key);
        if (iter != sourceMaps_.end()) {
            sourceInfo = GetSourceInfo(line, column, *(iter->second), key);
        } else {
            ans = ans + temp + "\n";
            continue;
        }
        if (sourceInfo.empty()) {
            continue;
        }
        temp.replace(openBracePos, closeBracePos - openBracePos + 1, sourceInfo);
        replace(temp.begin(), temp.end(), '\\', '/');
        ans = ans + temp + "\n";
    }
    if (ans.empty()) {
        return (NOT_FOUNDMAP + stackStr);
    }
    return ans;
}

void SourceMap::SplitSourceMap(const std::string& sourceMapData)
{
    std::lock_guard<std::mutex> lock(sourceMapMutex_);
    std::stringstream ss(sourceMapData);
    std::string tmp;
    std::string url;

    std::getline(ss, tmp);
    bool isUrl = true;
    std::shared_ptr<SourceMapData> mapData;
    while (std::getline(ss, tmp)) {
        if (isUrl && tmp.size() > REAL_SOURCE_INDEX) { // url
            url = tmp.substr(REAL_URL_INDEX, tmp.size() - REAL_SOURCE_INDEX);
            isUrl = false;
            mapData = std::make_shared<SourceMapData>();
            continue;
        }
        if (StringStartWith(tmp.c_str(), FLAG_SOURCES)) { // sources
            std::getline(ss, tmp);
            if (mapData) {
                mapData->sources_ = tmp;
                continue;
            }
        }
        if (StringStartWith(tmp.c_str(), FLAG_MAPPINGS)) { // mapping
            ExtractSourceMapData(tmp.substr(FLAG_MAPPINGS_LEN, tmp.size() - FLAG_MAPPINGS_LEN - 1), mapData);
            continue;
        }
        if (StringStartWith(tmp.c_str(), FLAG_ENTRY_PACKAGE_INFO)) { // entryPackageInfo
            if (mapData) {
                mapData->packageName_ = tmp;
                continue;
            }
        }
        if (StringStartWith(tmp.c_str(), FLAG_PACKAGE_INFO)) { // packageInfo
            if (mapData) {
                mapData->packageName_ = tmp;
                mapData->isPackageInfo_ = true;
                continue;
            }
        }
        if (StringStartWith(tmp.c_str(), FLAG_END)) {
            sourceMaps_[url] = mapData;
            isUrl = true;
        }
    }
}

void SourceMap::ExtractStackInfo(const std::string& stackStr, std::vector<std::string>& res)
{
    std::stringstream ss(stackStr);
    std::string tempStr;
    while (std::getline(ss, tempStr)) {
        res.push_back(tempStr);
    }
}

void SourceMap::ExtractSourceMapData(const std::string& allmappings, std::shared_ptr<SourceMapData>& curMapData)
{
    curMapData->mappings_ = HandleMappings(allmappings);
    // the first bit: the column after transferring.
    // the second bit: the source file.
    // the third bit: the row before transferring.
    // the fourth bit: the column before transferring.
    // the fifth bit: the variable name.
    for (const auto& mapping : curMapData->mappings_) {
        if (mapping == ";") {
            // plus a line for each semicolon
            curMapData->nowPos_.afterRow++,
            curMapData->nowPos_.afterColumn = 0;
            continue;
        }
        std::vector<int32_t> ans;

        if (!VlqRevCode(mapping, ans)) {
            return;
        }
        if (ans.empty()) {
            TAG_LOGE(AAFwkTag::JSENV, "decode sourcemap fail, mapping: %{public}s", mapping.c_str());
            break;
        }
        if (ans.size() == 1) {
            curMapData->nowPos_.afterColumn += ans[0];
            continue;
        }
        // after decode, assgin each value to the position
        curMapData->nowPos_.afterColumn += ans[0];
        curMapData->nowPos_.beforeRow += ans[INDEX_TWO];
        curMapData->nowPos_.beforeColumn += ans[INDEX_THREE];
        curMapData->afterPos_.push_back({
            curMapData->nowPos_.beforeRow,
            curMapData->nowPos_.beforeColumn,
            curMapData->nowPos_.afterRow,
            curMapData->nowPos_.afterColumn,
        });
    }
    curMapData->mappings_.clear();
    curMapData->mappings_.shrink_to_fit();
}

MappingInfo SourceMap::Find(int32_t row, int32_t col, const SourceMapData& targetMap, const std::string& key)
{
    if (row < 1 || col < 1 || targetMap.afterPos_.empty() || targetMap.sources_.empty()) {
        return MappingInfo {row, col, key};
    }
    row--;
    col--;
    // binary search
    int32_t left = 0;
    int32_t right = static_cast<int32_t>(targetMap.afterPos_.size()) - 1;
    int32_t res = 0;
    if (row > targetMap.afterPos_[targetMap.afterPos_.size() - 1].afterRow) {
        return MappingInfo { row + 1, col + 1, key };
    }
    while (right - left >= 0) {
        int32_t mid = (right + left) / 2;
        if ((targetMap.afterPos_[mid].afterRow == row && targetMap.afterPos_[mid].afterColumn > col) ||
             targetMap.afterPos_[mid].afterRow > row) {
            right = mid - 1;
        } else {
            res = mid;
            left = mid + 1;
        }
    }
    std::string sources = targetMap.sources_.substr(REAL_SOURCE_INDEX,
                                                    targetMap.sources_.size() - REAL_SOURCE_INDEX - 1);
    auto pos = sources.find(WEBPACK);
    if (pos != std::string::npos) {
        sources.replace(pos, sizeof(WEBPACK) - 1, "");
    }

    return MappingInfo {
        .row = targetMap.afterPos_[res].beforeRow + 1,
        .col = targetMap.afterPos_[res].beforeColumn + 1,
        .sources = sources,
    };
}

void SourceMap::ExtractKeyInfo(const std::string& sourceMap, std::vector<std::string>& sourceKeyInfo)
{
    uint32_t cnt = 0;
    std::string tempStr;
    for (uint32_t i = 0; i < sourceMap.size(); i++) {
        // reslove json file
        if (sourceMap[i] == DOUBLE_SLASH) {
            i++;
            tempStr += sourceMap[i];
            continue;
        }
        // cnt is used to represent a pair of double quotation marks: ""
        if (sourceMap[i] == '"') {
            cnt++;
        }
        if (cnt == INDEX_TWO) {
            sourceKeyInfo.push_back(tempStr);
            tempStr = "";
            cnt = 0;
        } else if (cnt == 1) {
            if (sourceMap[i] != '"') {
                tempStr += sourceMap[i];
            }
        }
    }
}

void SourceMap::GetPosInfo(const std::string& temp, int32_t start, std::string& line, std::string& column)
{
    // 0 for colum, 1 for row
    int32_t flag = 0;
    // find line, column
    for (int32_t i = start - 1; i > 0; i--) {
        if (temp[i] == ':') {
            flag += 1;
            continue;
        }
        if (flag == 0) {
            column = temp[i] + column;
        } else if (flag == 1) {
            line = temp[i] + line;
        } else {
            break;
        }
    }
}

std::vector<std::string> SourceMap::HandleMappings(const std::string& mapping)
{
    std::vector<std::string> keyInfo;
    std::string tempStr;
    for (uint32_t i = 0; i < mapping.size(); i++) {
        if (mapping[i] == DELIMITER_COMMA) {
            keyInfo.push_back(tempStr);
            tempStr = "";
        } else if (mapping[i] == DELIMITER_SEMICOLON) {
            if (tempStr != "") {
                keyInfo.push_back(tempStr);
            }
            tempStr = "";
            keyInfo.push_back(";");
        } else {
            tempStr += mapping[i];
        }
    }
    if (tempStr != "") {
        keyInfo.push_back(tempStr);
    }
    return keyInfo;
};

bool SourceMap::VlqRevCode(const std::string& vStr, std::vector<int32_t>& ans)
{
    const int32_t VLQ_BASE_SHIFT = 5;
    // binary: 100000
    uint32_t VLQ_BASE = 1 << VLQ_BASE_SHIFT;
    // binary: 011111
    uint32_t VLQ_BASE_MASK = VLQ_BASE - 1;
    // binary: 100000
    uint32_t VLQ_CONTINUATION_BIT = VLQ_BASE;
    uint32_t result = 0;
    uint32_t shift = 0;
    bool continuation = 0;
    for (uint32_t i = 0; i < vStr.size(); i++) {
        uint32_t digit = Base64CharToInt(vStr[i]);
        if (digit == DIGIT_NUM) {
            return false;
        }
        continuation = digit & VLQ_CONTINUATION_BIT;
        digit &= VLQ_BASE_MASK;
        result += digit << shift;
        if (continuation) {
            shift += VLQ_BASE_SHIFT;
        } else {
            bool isNegate = result & 1;
            result >>= 1;
            ans.push_back(isNegate ? -result : result);
            result = 0;
            shift = 0;
        }
    }
    if (continuation) {
        return false;
    }
    return true;
};

std::string SourceMap::GetSourceInfo(const std::string& line, const std::string& column,
    const SourceMapData& targetMap, const std::string& key)
{
    int32_t offSet = 0;
    std::string sourceInfo;
    MappingInfo mapInfo;
#if defined(WINDOWS_PLATFORM) || defined(MAC_PLATFORM)
        mapInfo = Find(StringToInt(line) - offSet + OFFSET_PREVIEW, StringToInt(column), targetMap, key);
#else
        mapInfo = Find(StringToInt(line) - offSet, StringToInt(column), targetMap, key);
#endif
    std::string sources = mapInfo.sources;
    std::string packageName = targetMap.packageName_;
    if (!packageName.empty()) {
        auto last = packageName.rfind('|');
        if (last != std::string::npos) {
            auto packageNameSize = targetMap.isPackageInfo_ ? FLAG_PACKAGE_INFO_SIZE : FLAG_ENTRY_PACKAGE_INFO_SIZE;
            sourceInfo = packageName.substr(packageNameSize, last - packageNameSize);
            return sourceInfo.append(" (" + sources + ":" + std::to_string(mapInfo.row) + ":" +
                std::to_string(mapInfo.col) + ")");
        }
    }
    sourceInfo = "(" + sources + ":" + std::to_string(mapInfo.row) + ":" + std::to_string(mapInfo.col) + ")";
    return sourceInfo;
}

ErrorPos SourceMap::GetErrorPos(const std::string& rawStack)
{
    size_t findLineEnd = rawStack.find("\n");
    if (findLineEnd == std::string::npos) {
        return std::make_pair(0, 0);
    }
    int32_t lineEnd = (int32_t)findLineEnd - 1;
    if (lineEnd < 1 || rawStack[lineEnd - 1] == '?') {
        return std::make_pair(0, 0);
    }

    uint32_t secondPos = rawStack.rfind(':', lineEnd);
    uint32_t fristPos = rawStack.rfind(':', secondPos - 1);

    std::string lineStr = rawStack.substr(fristPos + 1, secondPos - 1 - fristPos);
    std::string columnStr = rawStack.substr(secondPos + 1, lineEnd - 1 - secondPos);

    return std::make_pair(StringToInt(lineStr), StringToInt(columnStr));
}

void SourceMap::RegisterReadSourceMapCallback(ReadSourceMapCallback readFunc)
{
    std::lock_guard<std::mutex> lock(sourceMapMutex_);
    readSourceMapFunc_ = readFunc;
}

bool SourceMap::ReadSourceMapData(const std::string& hapPath, const std::string& sourceMapPath, std::string& content)
{
    std::lock_guard<std::mutex> lock(sourceMapMutex_);
    if (readSourceMapFunc_) {
        return readSourceMapFunc_(hapPath, sourceMapPath, content);
    }
    return false;
}

bool SourceMap::TranslateUrlPositionBySourceMap(std::string& url, int& line, int& column, std::string& packageName)
{
    auto iter = sourceMaps_.find(url);
    if (iter != sourceMaps_.end()) {
        return GetLineAndColumnNumbers(line, column, *(iter->second), url, packageName);
    }
    TAG_LOGE(AAFwkTag::JSENV, "stageMode sourceMaps find fail");
    return false;
}

bool SourceMap::GetLineAndColumnNumbers(int& line, int& column, SourceMapData& targetMap,
    std::string& url, std::string& packageName)
{
    int32_t offSet = 0;
    MappingInfo mapInfo;
#if defined(WINDOWS_PLATFORM) || defined(MAC_PLATFORM)
        mapInfo = Find(line - offSet + OFFSET_PREVIEW, column, targetMap, url);
#else
        mapInfo = Find(line - offSet, column, targetMap, url);
#endif
    if (mapInfo.row == 0 || mapInfo.col == 0) {
        return false;
    } else {
        line = mapInfo.row;
        column = mapInfo.col;
        url = mapInfo.sources;
        GetPackageName(targetMap, packageName);
        return true;
    }
}

void SourceMap::RegisterGetHapPathCallback(GetHapPathCallback getFunc)
{
    std::lock_guard<std::mutex> lock(sourceMapMutex_);
    getHapPathFunc_ = getFunc;
}

void SourceMap::GetHapPath(const std::string &bundleName, std::vector<std::string> &hapList)
{
    std::lock_guard<std::mutex> lock(sourceMapMutex_);
    if (getHapPathFunc_) {
        getHapPathFunc_(bundleName, hapList);
    }
}

void SourceMap::GetPackageName(const SourceMapData& targetMap, std::string& packageName)
{
    std::string packageInfo = targetMap.packageName_;
    if (!packageInfo.empty()) {
        auto last = packageInfo.rfind('|');
        if (last != std::string::npos) {
            auto packageNameSize = targetMap.isPackageInfo_ ? FLAG_PACKAGE_INFO_SIZE : FLAG_ENTRY_PACKAGE_INFO_SIZE;
            packageName = packageInfo.substr(packageNameSize, last - packageNameSize);
        }
    }
}
}   // namespace JsEnv
}   // namespace OHOS
