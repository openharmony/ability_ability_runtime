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

#ifndef OHOS_ABILITY_RUNTIME_ANI_COMMON_CACHE_MGR_H
#define OHOS_ABILITY_RUNTIME_ANI_COMMON_CACHE_MGR_H

#include <map>
#include <mutex>
#include <string>
#include "ani.h"

namespace OHOS {
namespace AppExecFwk {
constexpr const char *CLASSNAME_BOOLEAN = "std.core.Boolean";
constexpr const char *CLASSNAME_SHORT = "std.core.Short";
constexpr const char *CLASSNAME_INT = "std.core.Int";
constexpr const char *CLASSNAME_LONG = "std.core.Long";
constexpr const char *CLASSNAME_FLOAT = "std.core.Float";
constexpr const char *CLASSNAME_DOUBLE = "std.core.Double";
constexpr const char *CLASSNAME_STRING = "std.core.String";
constexpr const char *CLASSNAME_RECORD = "std.core.Record";

using AniCommonMethodCacheKey = std::pair<const char *, const char *>;

struct AniCommonCacheItem {
    ani_ref classRef_ = nullptr;
    std::map<AniCommonMethodCacheKey, ani_method> methodMap_;
};

class AniCommonCacheMgr {
public:
    static bool GetCachedClass(ani_env *env, const std::string &className, ani_class &cls);

    static bool GetCachedClassAndMethod(ani_env *env, const std::string &className,
        const AniCommonMethodCacheKey &methodKey, ani_class &cls, ani_method &method);

private:
    static bool InnerFindMethod(ani_env *env, const AniCommonMethodCacheKey &methodKey, ani_class cls,
        ani_method &method);

    static std::mutex mutex_;
    static std::map<std::string, AniCommonCacheItem> aniCache_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ANI_COMMON_CACHE_MGR_H
