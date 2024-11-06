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

#ifdef APP_DOMAIN_VERIFY_ENABLED
#include "ag_convert_callback_impl.h"
#include "app_domain_verify_mgr_client.h"
#endif

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
     * @return Error code of calling the function.
     */
    static int32_t ConvertToExplicitWant(Want& want);

    /**
     * GetCallerBundleName, get caller bundle name.
     *
     * @param callerBundleName The caller bundle name.
     * @return Error code of calling the function.
     */
    static int32_t GetCallerBundleName(std::string &callerBundleName);

    /**
     * IsAtomicServiceUrl, check if the want contains atomic service url.
     *
     * @param want The implicit want.
     * @return Flag if the want contains atomic service url.
     */
    static bool IsAtomicServiceUrl(const Want& want);
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_WANT_UTILS_H
