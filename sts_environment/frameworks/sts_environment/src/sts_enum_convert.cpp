/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "sts_enum_convert.h"
#include "hilog_tag_wrapper.h"
namespace OHOS {
namespace AAFwk {
//     enum AreaMode {
//     EL1 = 0,
//     EL2 = 1,
//     EL3 = 2,
//     EL4 = 3,
//     EL5 = 4
//   }
int EnumConvertUtils::AreaMode_ConvertSts2Native(const int index)
{
    return index;
}
int EnumConvertUtils::AreaMode_ConvertNative2Sts(const int nativeValue)
{
    return nativeValue;
}

//   enum WindowMode {
//     WINDOW_MODE_UNDEFINED = 0,
//     WINDOW_MODE_FULLSCREEN = 1,
//     WINDOW_MODE_SPLIT_PRIMARY = 100,
//     WINDOW_MODE_SPLIT_SECONDARY = 101,
//     WINDOW_MODE_FLOATING = 102
//   }
int EnumConvertUtils::WindowMode_ConvertSts2Native(const int index)
{

    if (index < 0 || index >= WindowModeArray.size()) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "WindowMode_ConvertSts2Native failed index:%{public}d", index);
        return 0;
    }
    return WindowModeArray[index];
}
int EnumConvertUtils::WindowMode_ConvertNative2Sts(const int nativeValue)
{
    for (int index = 0; index < WindowModeArray.size(); index++) {
        if (nativeValue == WindowModeArray[index]) {
            return index;
        }
    }
    TAG_LOGE(AAFwkTag::STSRUNTIME, "WindowMode_ConvertNative2Sts failed nativeValue:%{public}d", nativeValue);
    return 0;
}
}  // namespace AAFwk
}  // namespace OHOS
