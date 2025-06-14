/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_WANT_UTILS_H
#define OHOS_ABILITY_RUNTIME_WANT_UTILS_H

#include "want.h"

namespace OHOS {
namespace AAFwk {
/**
 * @class WantUtils
 * provides want utilities.
 */
class WantUtils final {
public:
    /**
     * ConvertToExplicitWant, convert implicit want to explicit want.
     *
     * @param want The implicit want.
     * @param targetType AG find specific targetType.
     * @return Error code of calling the function.
     */
    static int32_t ConvertToExplicitWant(Want &want, uint32_t &targetType);

    /**
     * GetCallerBundleName, get caller bundle name.
     *
     * @param callerBundleName The caller bundle name.
     * @return Error code of calling the function.
     */
    static int32_t GetCallerBundleName(std::string &callerBundleName);

    /**
     * IsShortUrl, check if the want url is short url.
     *
     * @param want The implicit want.
     * @return Flag if the want url is short url.
     */
    static bool IsShortUrl(const Want &want);

    /**
     * IsAtomicService, check if the targetType is AtomicService.
     *
     * @param targetType targetType to be judged.
     * @return Flag if the targetType is AtomicService.
     */
    static bool IsAtomicService(uint32_t targetType);

    /**
     * IsNormalApp, check if the targetType is App.
     *
     * @param targetType targetType to be judged.
     * @return Flag if the targetType is App.
     */
    static bool IsNormalApp(uint32_t targetType);
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_WANT_UTILS_H