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

#ifndef OHOS_AAFWK_HILOG_TAG_WRAPPER_H
#define OHOS_AAFWK_HILOG_TAG_WRAPPER_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>

namespace OHOS::AAFwk {
enum class AAFwkLogTag : uint32_t {
    DEFAULT = 0xD001300,        // 0XD001300
};

class MockLogger {
public:
    static MockLogger instance;
    MOCK_METHOD(void, PrintLog, (const std::string &), ());
};
}

using AAFwkTag = OHOS::AAFwk::AAFwkLogTag;

#define AAFWK_PRINT_LOG(tag, fmt, ...)                                                           \
    do {                                                                                                \
        OHOS::AAFwk::MockLogger::instance.PrintLog(fmt);                                                \
    } while (0)

#define TAG_LOGD(tag, fmt, ...) AAFWK_PRINT_LOG(tag, fmt, ##__VA_ARGS__)
#define TAG_LOGI(tag, fmt, ...) AAFWK_PRINT_LOG(tag, fmt, ##__VA_ARGS__)
#define TAG_LOGW(tag, fmt, ...) AAFWK_PRINT_LOG(tag, fmt, ##__VA_ARGS__)
#define TAG_LOGE(tag, fmt, ...) AAFWK_PRINT_LOG(tag, fmt, ##__VA_ARGS__)
#define TAG_LOGF(tag, fmt, ...) AAFWK_PRINT_LOG(tag, fmt, ##__VA_ARGS__)

#endif