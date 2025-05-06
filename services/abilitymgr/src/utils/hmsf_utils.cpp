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

#include "utils/hmsf_utils.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

namespace OHOS {
namespace AbilityRuntime {
#define HMFS_MONITOR_FL 0x00000002
#define HMF_IOCTL_HW_GET_FLAGS _IOR(0xf5, 70, unsigned int)
#define HMF_IOCTL_HW_SET_FLAGS _IOR(0xf5, 71, unsigned int)
void HmfsUtils::AddDeleteDfx(const std::string &path)
{
    int32_t fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "open dfx path %{public}s failed", path.c_str());
        return;
    }
    unsigned int flags = 0;
    int32_t ret = ioctl(fd, HMF_IOCTL_HW_GET_FLAGS, &flags);
    if (ret < 0) {
        TAG_LOGD(AAFwkTag::ABILITYMGR,  "check dfx flag path %{public}s failed errno:%{public}d", path.c_str(), errno);
        close(fd);
        return;
    }
    if (flags & HMFS_MONITOR_FL) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "Delete Control flag is already set");
        close(fd);
        return;
    }
    flags |= HMFS_MONITOR_FL;
    ret = ioctl(fd, HMF_IOCTL_HW_SET_FLAGS, &flags);
    if (ret < 0) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "Add dfx flag failed errno:%{public}d path %{public}s", errno, path.c_str());
        close(fd);
        return;
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR, "Delete Control flag of %{public}s is set succeed", path.c_str());
    close(fd);
    return;
}

}  // namespace AbilityRuntime
}  // namespace OHOS
