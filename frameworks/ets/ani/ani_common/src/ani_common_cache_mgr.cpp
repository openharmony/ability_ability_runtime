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

#include "ani_common_cache_mgr.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
std::mutex AniCommonCacheMgr::mutex_;
std::map<std::string, AniCommonCacheItem> AniCommonCacheMgr::aniCache_ = {
    { CLASSNAME_BOOLEAN, {} },
    { CLASSNAME_SHORT, {} },
    { CLASSNAME_INT, {} },
    { CLASSNAME_LONG, {} },
    { CLASSNAME_FLOAT, {} },
    { CLASSNAME_DOUBLE, {} },
    { CLASSNAME_STRING, {} },
    { CLASSNAME_RECORD, {} },
};

bool AniCommonCacheMgr::GetCachedClass(ani_env *env, const std::string &className, ani_class &cls)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::BRIDGE, "null env");
        return false;
    }

    std::lock_guard lock(mutex_);
    const auto iter = aniCache_.find(className);
    if (iter == aniCache_.end()) {
        TAG_LOGE(AAFwkTag::BRIDGE, "Not support cache %{public}s", className.c_str());
        return false;
    }
    if (iter->second.classRef_ != nullptr) {
        cls = reinterpret_cast<ani_class>(iter->second.classRef_);
        return true;
    }

    ani_status status = env->FindClass(className.c_str(), &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::BRIDGE, "FindClass %{public}s failed %{public}d", className.c_str(), status);
        return false;
    }
    ani_ref ref = nullptr;
    status = env->GlobalReference_Create(cls, &ref);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::BRIDGE, "GlobalReference_Create %{public}s failed %{public}d", className.c_str(), status);
        return false;
    }
    iter->second.classRef_ = ref;
    return true;
}

bool AniCommonCacheMgr::GetCachedClassAndMethod(ani_env *env, const std::string &className,
    const AniCommonMethodCacheKey &methodKey, ani_class &cls, ani_method &method)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::BRIDGE, "null env");
        return false;
    }

    std::lock_guard lock(mutex_);
    const auto iter = aniCache_.find(className);
    if (iter == aniCache_.end()) {
        TAG_LOGE(AAFwkTag::BRIDGE, "Not support cache %{public}s", className.c_str());
        return false;
    }
    if (iter->second.classRef_ == nullptr) {
        ani_status status = env->FindClass(className.c_str(), &cls);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::BRIDGE, "FindClass %{public}s failed %{public}d", className.c_str(), status);
            return false;
        }
        ani_ref ref = nullptr;
        status = env->GlobalReference_Create(cls, &ref);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::BRIDGE,
                "GlobalReference_Create %{public}s failed %{public}d", className.c_str(), status);
            return false;
        }
        iter->second.classRef_ = ref;
    }

    cls = reinterpret_cast<ani_class>(iter->second.classRef_);
    const auto methodIter = iter->second.methodMap_.find(methodKey);
    if (methodIter == iter->second.methodMap_.end()) {
        if (!InnerFindMethod(env, methodKey, cls, method)) {
            return false;
        }
        iter->second.methodMap_.emplace(methodKey, method);
        return true;
    }
    if (methodIter->second == nullptr) {
        if (!InnerFindMethod(env, methodKey, cls, method)) {
            return false;
        }
        methodIter->second = method;
        return true;
    }
    method = methodIter->second;
    return true;
}

bool AniCommonCacheMgr::InnerFindMethod(ani_env *env, const AniCommonMethodCacheKey &methodKey, ani_class cls,
    ani_method &method)
{
    ani_status status =
        env->Class_FindMethod(cls, methodKey.first, methodKey.second, &method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::BRIDGE, "Class_FindMethod %{public}s signature %{public}s failed %{public}d",
            methodKey.first, methodKey.second, status);
        return false;
    }
    return true;
}
} // namespace AppExecFwk
} // namespace OHOS
