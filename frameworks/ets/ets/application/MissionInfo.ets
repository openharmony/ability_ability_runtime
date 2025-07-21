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

import Want from '@ohos.app.ability.Want';
export interface MissionInfo {
  missionId: int;
  runningState: int;
  lockedState: boolean;
  timestamp: string;
  want: Want;
  label: string;
  iconPath: string;
  continuable: boolean;
  abilityState: int;
  unclearable: boolean;
}

class MissionInfoInner implements MissionInfo {
  public missionId: int;
  public runningState: int;
  public lockedState: boolean;
  public timestamp: string = '';
  public want: Want = {};
  public label: string = '';
  public iconPath: string = '';
  public continuable: boolean;
  public abilityState: int;
  public unclearable: boolean;
}