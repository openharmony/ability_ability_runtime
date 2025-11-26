/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"),
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

/**
 * @file
 * @kit AbilityKit
 */

import image from '@ohos.multimedia.image';

export interface MissionListener {
  onMissionCreated(mission: int): void;
  onMissionDestroyed(mission: int): void;
  onMissionSnapshotChanged(mission: int): void;
  onMissionMovedToFront(mission: int): void;
  onMissionLabelUpdated(mission: int): void;
  onMissionIconUpdated(mission: int, icon: image.PixelMap): void;
  onMissionClosed(mission: int): void;
}

class MissionListenerInner implements MissionListener {
  onMissionCreated(mission: int): void {
  }
  onMissionDestroyed(mission: int): void {
  }
  onMissionSnapshotChanged(mission: int): void {
  }
  onMissionMovedToFront(mission: int): void {
  }
  onMissionLabelUpdated(mission: int): void {
  }
  onMissionIconUpdated(mission: int, icon: image.PixelMap): void {
  }
  onMissionClosed(mission: int): void {
  }
}