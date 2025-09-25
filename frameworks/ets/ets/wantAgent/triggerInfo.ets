/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import Want from '@ohos.app.ability.Want';
import StartOptions from '@ohos.app.ability.StartOptions';
import { RecordData } from '@ohos.base';

export interface TriggerInfo {
  code: int;
  want?: Want;
  permission?: string;
  extraInfo?: Record<string, RecordData>;
  extraInfos?: Record<string, RecordData>;
  startOptions?: StartOptions;
}

class TriggerInfoImpl implements TriggerInfo {
  public code: int;
  public want?: Want;
  public permission?: string;
  public extraInfo?: Record<string, RecordData>;
  public extraInfos?: Record<string, RecordData>;
  public startOptions?: StartOptions;
}
