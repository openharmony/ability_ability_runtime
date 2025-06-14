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

#ifndef MOCK_FFRT_H
#define MOCK_FFRT_H

#include <cinttypes>
#include <errno.h>
#include <functional>
#include <string>

constexpr int32_t ffrt_qos_background = 0;
namespace ffrt {
struct task_attr {
    inline void qos(int32_t) {}
    inline void name(const std::string &) {}
    inline void delay(int64_t) {}
};
void submit(std::function<void()> &&task, task_attr)
{
    if (task) {
        task();
    }
}
}  // namespace ffrt
#endif // MOCK_FFRT_H