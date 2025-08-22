/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_SUPPORT_SYSTEM_ABILITY_PERMISSION_H
#define OHOS_ABILITY_SUPPORT_SYSTEM_ABILITY_PERMISSION_H

#include <string>
#include "hilog_tag_wrapper.h"
#include "parameters.h"

namespace OHOS {
namespace AAFwk {
namespace SupportSystemAbilityPermission {
constexpr std::array SUPPORTED_UIDS = std::array{1001, 1002, 1003, 1004, 1006, 1007, 1008, 1009, 1010, 1013, 1014, 1015,
        1016, 1017, 1018, 1019, 1021, 1022, 1023, 1024, 1027, 1028, 1029, 1032, 1036, 1037, 1041, 1042, 1043, 1047,
        1048, 1065, 1077, 1080, 1088, 1089, 1090, 1096, 1097, 1098, 1099, 1100, 1101, 1102, 1103, 1111, 1112, 1113,
        1114, 1115, 1201, 1202, 1212, 1250, 2000, 2001, 3001, 3006, 3007, 3009, 3010, 3011, 3012, 3013, 3019, 3020,
        3021, 3022, 3023, 3024, 3025, 3026, 3027, 3028, 3029, 3030, 3031, 3032, 3033, 3034, 3035, 3036, 3037, 3038,
        3039, 3040, 3041, 3042, 3043, 3044, 3045, 3046, 3047, 3048, 3049, 3050, 3051, 3052, 3053, 3054, 3055, 3056,
        3057, 3058, 3059, 3060, 3061, 3062, 3063, 3064, 3065, 3068, 3070, 3071, 3072, 3073, 3074, 3075, 3076, 3077,
        3079, 3080, 3081, 3085, 3090, 3093, 3094, 3095, 3096, 3097, 3100, 3101, 3111, 3127, 3333, 3350, 3500, 3508,
        3510, 3515, 3520, 3521, 3522, 3553, 3562, 3815, 3816, 3817, 3818, 3819, 3820, 3821, 3822, 3823, 3824, 4444,
        4998, 4999, 5000, 5001, 5002, 5003, 5004, 5005, 5006, 5007, 5200, 5201, 5206, 5300, 5513, 5520, 5521, 5522,
        5523, 5524, 5525, 5526, 5527, 5528, 5529, 5530, 5535, 5555, 5557, 6000, 6066, 6100, 6101, 6104, 6226, 6227,
        6253, 6254, 6255, 6256, 6257, 6258, 6259, 6260, 6261, 6262, 6263, 6264, 6265, 6266, 6267, 6268, 6666, 6667,
        6668, 6688, 6696, 6699, 6700, 6701, 7000, 7001, 7002, 7003, 7004, 7005, 7006, 7007, 7008, 7008, 7009, 7010,
        7011, 7012, 7013, 7014, 7015, 7015, 7016, 7017, 7018, 7020, 7021, 7022, 7023, 7024, 7025, 7027, 7028, 7030,
        7031, 7032, 7033, 7034, 7035, 7036, 7055, 7056, 7058, 7071, 7072, 7073, 7080, 7099, 7100, 7101, 7110, 7111,
        7119, 7120, 7123, 7140, 7166, 7200, 7211, 7212, 7224, 7234, 7259, 7300, 7336, 7337, 7338, 7339, 7340, 7342,
        7343, 7344, 7352, 7356, 7391, 7444, 7445, 7500, 7508, 7518, 7555, 7558, 7654, 7655, 7666, 7680, 7700, 7710,
        7748, 7777, 7778, 7779, 7780, 7788, 7789, 7799, 7800, 7811, 7812, 7842, 7851, 7878, 7886, 7888, 7890, 7900,
        7958, 7992, 7993, 7994, 7995, 7996, 7997, 7998, 7999, 8000, 8002, 8020, 8030, 8050, 8064, 8100, 8666, 8668,
        8866, 8879, 8888, 9998, 10000, 65872, 65878, 65898, 65936};
inline bool IsSupportSaCallPermission()
{
    TAG_LOGD(AAFwkTag::DEFAULT, "call IsSupportSaCallPermission, CallingUid: %{public}d", IPCSkeleton::GetCallingUid());
    bool hasSaCallPermission =
        std::find(SUPPORTED_UIDS.begin(), SUPPORTED_UIDS.end(), IPCSkeleton::GetCallingUid()) != SUPPORTED_UIDS.end();
    return hasSaCallPermission;
}
}  // namespace SupportSystemAbilityPermission
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_SUPPORT_SYSTEM_ABILITY_PERMISSION_H