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

#include "file_monitor.h"

#include <filesystem>
#include <fcntl.h>
#include <iostream>
#include <sys/ioctl.h>
#include <unistd.h>

#include "hilog_tag_wrapper.h"

#define HMFS_MONITOR_FL 0x00000002
#define HMFS_IOCTL_HW_GET_FLAGS _IOR(0xf5, 70, unsigned int)
#define HMFS_IOCTL_HW_SET_FLAGS _IOR(0xf5, 71, unsigned int)

namespace OHOS {
namespace AAFwk {
void FileMonitor::SetDeleteMonitorFlag(const char *filePath)
{
    TAG_LOGD(AAFwkTag::DEFAULT, "called.");
    int32_t fd = open(filePath, O_RDONLY);
    if (fd < 0) {
        TAG_LOGE(AAFwkTag::DEFAULT, "open file %{private}s failed", filePath);
        return;
    }
    unsigned int flags = 0;
    int ret = ioctl(fd, HMFS_IOCTL_HW_GET_FLAGS, &flags);
    if (ret < 0) {
        TAG_LOGE(AAFwkTag::DEFAULT, "Get flags failed, errno: %{public}d, filePath:%{private}s",
            errno, filePath);
        close(fd);
        return;
    }

    if (flags & HMFS_MONITOR_FL) {
        TAG_LOGD(AAFwkTag::DEFAULT, "flag is already set: %{private}s", filePath);
        close(fd);
        return;
    }

    flags |= HMFS_MONITOR_FL;
    ret = ioctl(fd, HMFS_IOCTL_HW_SET_FLAGS, &flags);
    if (ret < 0) {
        TAG_LOGE(AAFwkTag::DEFAULT, "Set flags failed, errno: %{public}d, filePath:%{private}s",
            errno, filePath);
        close(fd);
        return;
    }

    TAG_LOGI(AAFwkTag::DEFAULT, "Set flag success, filePath:%{private}s", filePath);
    close(fd);
}

void FileMonitor::SetDBDeleteMonitorFlag(const char *dbFolder)
{
    TAG_LOGD(AAFwkTag::DEFAULT, "called, folder: %{public}s", dbFolder);
    std::filesystem::path dirPath = dbFolder;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(dirPath)) {
        if (entry.is_directory()) {
            continue;
        }
        auto extension = entry.path().extension();
        if (extension == ".db" || extension == ".db-wal" || extension == ".db-shm") {
            SetDeleteMonitorFlag(entry.path().c_str());
        }
    }
}
}  // namespace AAFwk
}  // namespace OHOS
