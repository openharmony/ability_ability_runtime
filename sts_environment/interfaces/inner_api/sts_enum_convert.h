/*
 * Copyright (c) 2021-20225 Huawei Device Co., Ltd.
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
#ifndef OHOS_ABILITY_BASE_ENUM_CONVERT_UTILS_H
#define OHOS_ABILITY_BASE_ENUM_CONVERT_UTILS_H
#include <array>
#include <string>

namespace OHOS {
namespace AAFwk {

class EnumConvertUtils {
public:
    //  enum AreaMode {
    //     EL1 = 0,
    //     EL2 = 1,
    //     EL3 = 2,
    //     EL4 = 3,
    //     EL5 = 4
    //   }
    static int AreaMode_ConvertSts2Native(const int index);
    static int AreaMode_ConvertNative2Sts(const int nativeValue);

    static int WindowMode_ConvertSts2Native(const int index);
    static int WindowMode_ConvertNative2Sts(const int nativeValue);
    

private:
    //   enum WindowMode {
    //     WINDOW_MODE_UNDEFINED = 0,
    //     WINDOW_MODE_FULLSCREEN = 1,
    //     WINDOW_MODE_SPLIT_PRIMARY = 100,
    //     WINDOW_MODE_SPLIT_SECONDARY = 101,
    //     WINDOW_MODE_FLOATING = 102
    //   }
    static constexpr std::array<int, 5> WindowModeArray = {0, 1, 100, 101, 102};

};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_BASE_ENUM_CONVERT_UTILS_H
