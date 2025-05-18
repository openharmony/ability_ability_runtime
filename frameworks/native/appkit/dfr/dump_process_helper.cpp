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

#include "dump_process_helper.h"

#include "file_ex.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace DumpProcessHelper {
constexpr int JS_ERROR_RSS_MEMINFO_TOKEN_NUM = 2;
constexpr int JS_ERROR_RSS_MEMINFO_DECIMAL_BASE = 10;
constexpr int JS_ERROR_RSS_MEMINFO_PAGE_SIZE_KB = 4096;
constexpr int JS_ERROR_RSS_MEMINFO_SIZE_KB = 1000;

uint64_t GetProcRssMemInfo()
{
    std::string statmPath = "/proc/self/statm";
    std::string readContent;

    if (!LoadStringFromFile(statmPath, readContent)) {
        return 0;
    }

    std::vector<std::string> tokens;
    SplitStr(readContent, " ", tokens);
    if (tokens.size() < JS_ERROR_RSS_MEMINFO_TOKEN_NUM) {
        return 0;
    }

    std::string rssStr = tokens.at(1);
    uint64_t rss = static_cast<uint64_t>(strtoull(rssStr.c_str(), nullptr, JS_ERROR_RSS_MEMINFO_DECIMAL_BASE));
    if (rss == 0) {
        return 0;
    }

    rss = (rss * JS_ERROR_RSS_MEMINFO_PAGE_SIZE_KB) / JS_ERROR_RSS_MEMINFO_SIZE_KB;
    return rss;
}
} // namespace DumpProcessHelper
} // namespace AppExecFwk
} // namespace OHOS